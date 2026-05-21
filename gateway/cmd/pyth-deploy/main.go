// Command pyth-deploy is a one-shot devnet ops tool that initialises the
// deployed pyth-adapter: it creates the AdapterConfig, registers the SOL/USD
// feed (FeedCache PDA) and runs a first refresh against the Pyth sponsored
// account, then prints the resulting canonical view. Idempotent: existing
// accounts are skipped.
//
// Usage (from gateway/):
//
//	go run ./cmd/pyth-deploy \
//	  -program A6xjw8jkJTFjpjHCRSFxVt1d1KbBZdh3XBNYvTfLZxP2 \
//	  -payer C:/solana/devnet.json \
//	  -crank ../contracts/pyth-adapter/crank-keypair.json \
//	  -rpc https://api.devnet.solana.com \
//	  -feed-id ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d \
//	  -pyth-account 7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE \
//	  -label SOL/USD
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/shinkalabs/andromeda-gateway/internal/oraclerelay"
)

func main() {
	var (
		programStr = flag.String("program", "", "pyth-adapter program id (base58)")
		payerPath  = flag.String("payer", "", "deployer/backup keypair file (also fee payer)")
		crankPath  = flag.String("crank", "", "crank authority keypair file")
		rpcURL     = flag.String("rpc", "https://api.devnet.solana.com", "Solana RPC URL")
		feedIDHex  = flag.String("feed-id", "", "32-byte Pyth feed id (hex)")
		pythAcct   = flag.String("pyth-account", "", "Pyth PriceUpdateV2 source account (base58)")
		_          = flag.String("label", "SOL/USD", "feed label (informational)")
	)
	flag.Parse()

	programID := solana.MustPublicKeyFromBase58(*programStr)
	payer, err := solana.PrivateKeyFromSolanaKeygenFile(*payerPath)
	must(err, "load payer")
	crank, err := solana.PrivateKeyFromSolanaKeygenFile(*crankPath)
	must(err, "load crank")
	priceUpdate := solana.MustPublicKeyFromBase58(*pythAcct)

	feedBytes, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(*feedIDHex), "0x"))
	must(err, "decode feed-id")
	if len(feedBytes) != 32 {
		log.Fatalf("feed-id must be 32 bytes, got %d", len(feedBytes))
	}
	var feedID [32]byte
	copy(feedID[:], feedBytes)

	cl := rpc.New(*rpcURL)
	ctx := context.Background()

	configPDA, _, err := oraclerelay.AdapterConfigPDA(programID)
	must(err, "derive config pda")
	cachePDA, bump, err := oraclerelay.FeedCachePDA(programID, feedID)
	must(err, "derive feed cache pda")

	fmt.Printf("program       = %s\n", programID)
	fmt.Printf("authority     = %s (crank)\n", crank.PublicKey())
	fmt.Printf("backup/payer  = %s\n", payer.PublicKey())
	fmt.Printf("config PDA    = %s\n", configPDA)
	fmt.Printf("feed cache PDA= %s (bump %d)\n\n", cachePDA, bump)

	// 1) init_adapter (skip if config already exists).
	if exists(ctx, cl, configPDA) {
		fmt.Println("[1/3] init_adapter: config already exists — skipped")
	} else {
		ix := initAdapterIx(programID, configPDA, crank.PublicKey(), payer.PublicKey())
		sig := send(ctx, cl, payer, []solana.Instruction{ix}, payer, crank)
		fmt.Printf("[1/3] init_adapter: %s\n", sig)
	}

	// 2) init_feed_cache (skip if cache already exists). Permissionless: payer
	// just funds the rent.
	if exists(ctx, cl, cachePDA) {
		fmt.Println("[2/3] init_feed_cache: cache already exists — skipped")
	} else {
		ix := oraclerelay.InitFeedCacheIx(programID, configPDA, cachePDA, payer.PublicKey(), feedID, bump)
		sig := send(ctx, cl, payer, []solana.Instruction{ix}, payer)
		fmt.Printf("[2/3] init_feed_cache: %s\n", sig)
	}

	// 3) refresh_feed (permissionless: any fee payer).
	ix := oraclerelay.RefreshFeedIx(programID, configPDA, cachePDA, priceUpdate)
	sig := send(ctx, cl, payer, []solana.Instruction{ix}, payer)
	fmt.Printf("[3/3] refresh_feed: %s\n\n", sig)

	// Verify the canonical view written into the FeedCache.
	acct, err := cl.GetAccountInfoWithOpts(ctx, cachePDA, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed})
	must(err, "read feed cache")
	d := acct.Value.Data.GetBinary()
	fmt.Println("FeedCache canonical view:")
	fmt.Printf("  feed_id      = %s\n", hex.EncodeToString(d[0:32]))
	fmt.Printf("  price        = %d (decimal 1e8 → $%.8f)\n", int64(binary.LittleEndian.Uint64(d[32:40])), float64(int64(binary.LittleEndian.Uint64(d[32:40])))/1e8)
	fmt.Printf("  confidence   = %d\n", binary.LittleEndian.Uint64(d[40:48]))
	fmt.Printf("  publish_time = %d\n", int64(binary.LittleEndian.Uint64(d[56:64])))
	fmt.Println("\nOK — adapter initialised and SOL/USD feed refreshed on devnet.")
}

// initAdapterIx builds disc 0. Accounts: config(w), authority(signer ro),
// payer(signer w), rent, system. Data: [0][authority(32)][backup(32)].
func initAdapterIx(programID, config, authority, backup solana.PublicKey) solana.Instruction {
	data := make([]byte, 0, 1+32+32)
	data = append(data, 0) // disc init_adapter
	data = append(data, authority.Bytes()...)
	data = append(data, backup.Bytes()...)
	accounts := solana.AccountMetaSlice{
		{PublicKey: config, IsSigner: false, IsWritable: true},
		{PublicKey: authority, IsSigner: true, IsWritable: false},
		{PublicKey: backup, IsSigner: true, IsWritable: true}, // payer == backup here
		{PublicKey: solana.SysVarRentPubkey, IsSigner: false, IsWritable: false},
		{PublicKey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(programID, accounts, data)
}

func exists(ctx context.Context, cl *rpc.Client, pk solana.PublicKey) bool {
	res, err := cl.GetAccountInfoWithOpts(ctx, pk, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed})
	return err == nil && res != nil && res.Value != nil
}

func send(ctx context.Context, cl *rpc.Client, feePayer solana.PrivateKey, ixs []solana.Instruction, signers ...solana.PrivateKey) solana.Signature {
	bh, err := cl.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	must(err, "blockhash")
	tx, err := solana.NewTransaction(ixs, bh.Value.Blockhash, solana.TransactionPayer(feePayer.PublicKey()))
	must(err, "build tx")
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		for i := range signers {
			if signers[i].PublicKey().Equals(key) {
				return &signers[i]
			}
		}
		return nil
	})
	must(err, "sign tx")
	sig, err := cl.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{PreflightCommitment: rpc.CommitmentConfirmed})
	must(err, "send tx")
	// Confirm.
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(800 * time.Millisecond)
		st, err := cl.GetSignatureStatuses(ctx, true, sig)
		if err != nil || st == nil || len(st.Value) == 0 || st.Value[0] == nil {
			continue
		}
		if st.Value[0].Err != nil {
			log.Fatalf("tx %s failed on-chain: %v", sig, st.Value[0].Err)
		}
		if st.Value[0].ConfirmationStatus == rpc.ConfirmationStatusConfirmed ||
			st.Value[0].ConfirmationStatus == rpc.ConfirmationStatusFinalized {
			return sig
		}
	}
	log.Fatalf("tx %s not confirmed before deadline", sig)
	return sig
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
