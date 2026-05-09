package webhooks

import "time"

// nowFn is overridable in tests.
var nowFn = time.Now
