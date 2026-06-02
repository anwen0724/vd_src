# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h18_gpio_apb_scope`
- benchmark: `hackatdac18`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- evaluated runs: 6
- expected GT cases: `H18-001`, `H18-004`, `H18-005`, `H18-006`, `H18-008`

## 2. GT Cases

| case_id | brief meaning |
|---|---|
| `H18-001` | UDMA/SPI master and SoC control APB address ranges overlap. |
| `H18-004` | GPIO lock register is directly software-writable. |
| `H18-005` | Reset clears the GPIO lock control state. |
| `H18-006` | Incorrect APB/peripheral address range enables aliasing. |
| `H18-008` | GPIO, UDMA/SPI, and SoC control APB address ranges overlap. |

## 3. Per-run Results

| model | rep | H18-001 | H18-004 | H18-005 | H18-006 | H18-008 | extra FP |
|---|---:|---|---|---|---|---|---:|
| `deepseek_v4_pro` | 1 | FN | TP | FN | FN | FN | 2 |
| `deepseek_v4_pro` | 2 | FN | TP | FN | FN | FN | 1 |
| `deepseek_v4_pro` | 3 | FN | TP | FN | FN | FN | 0 |
| `gpt_5_5` | 1 | Partial | TP | FN | Partial | TP | 0 |
| `gpt_5_5` | 2 | FN | Partial | FN | FN | FN | 0 |
| `gpt_5_5` | 3 | FN | FN | FN | FN | FN | 1 |

## 4. Main Observations

Both models can find the mutable GPIO lock register issue, especially DeepSeek. Neither model finds the reset-lifecycle case `H18-005`.

Only GPT rep1 identifies the APB address overlap family. That finding is sufficient for `H18-008`, and partially covers `H18-001` and `H18-006`, but most runs miss the address-map cases entirely.

Several findings report generic GPIO/APB missing permission or PADOUTSET/PADOUTCLR lock bypass. These are not scored as official GT hits unless they identify `REG_GPIOLOCK` self-writability or address-overlap semantics.

## 5. Notes for Later Scoring

For `H18-004`, require `REG_GPIOLOCK` or `r_gpio_lock` direct APB writability. For `H18-005`, require reset clearing `r_gpio_lock`. For address-map cases, require actual overlapping ranges and APB independent selection evidence; generic APB no-access-control claims are not enough.
