# Restore progress replay

`restored-progress-26A434.json` contains only operation IDs, percentages and
weights from two local Mac transcripts for build 26A434: a successful Erase
restore and a successful Update/Revive. The messages retain their original
order and are expressed as GUI worker events. No identifiers, authorization
data or payloads are included. The final success status is deliberately omitted
so a replay cannot claim completion from progress messages alone.

The Erase trace used to reach only 88.9959% before the final status because
operations 12 and 15 report `Progress = -1`. Apple's accumulator credits their
full weights. This brings the weighted total to 100%; Zalivka reserves the
displayed 100% for the successful final status and therefore shows 99% first.

The Update trace advertises weights for operations 13 and 14 without sending
progress for either operation. Even Apple's accumulation rule only reaches 41%
from these messages. The test preserves this limitation instead of assuming
unreported operations have completed.

The calculation was checked against the locally extracted Apple binaries:

- MobileDevice arm64e: `PRProgressDecodeWeights` at `0x1553b8` reads
  `operation_progresses` as completed weight units, capped at the operation's
  weight. `PRProgressComputeOverallProgress` at `0x1557c0` credits the full
  weight for `-1`, otherwise retains the maximum integer contribution, and
  truncates the overall percentage.
- `restored_external` 26A434 uses the same accumulation at `0x1000645a4`.
  Its progress/UI function at `0x100026670` passes that result to the display
  update. This establishes the accumulation rule, not a measurement of the
  physical screen during these recorded restores.
