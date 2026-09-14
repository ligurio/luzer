local luzer = require("luzer")

-- The counters and the PC table are registered with libFuzzer before the
-- run loop, so they appear in the startup module report. The default
-- luzer table has 2^18 entries and CTest looks for it there by size; the
-- native instrumentation of the shared library is far smaller. The PC
-- table is registered with the same length, which libFuzzer verifies at
-- startup and aborts on if it does not match.
luzer.Fuzz(function() end, nil, { runs = 1 })
