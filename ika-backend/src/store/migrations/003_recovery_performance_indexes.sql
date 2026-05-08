-- Cover quorum contribution listing by session.

CREATE INDEX IF NOT EXISTS recovery_quorum_contributions_session_id_idx
  ON recovery_quorum_contributions(session_id, id);
