<!--
SPDX-License-Identifier: GPL-2.0-only
Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
-->

# License scope and attribution

Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG

Files carrying `SPDX-License-Identifier: GPL-2.0-only` are licensed under the GNU General Public License, version 2 only. The full text is in [LICENSE](LICENSE).

This is a file-specific declaration, not a relicensing of upstream material. Existing authorship credits and third-party license terms remain in effect. Copyright notices marked "GGSEC modifications and additions" refer only to those contributions.

## GPL-2.0-only files

- `Makefile`
- `README.md`
- `RESULTS.md`
- `kernel/Makefile`
- `kernel/banner-noroot.sh`
- `kernel/banner.sh`
- `kernel/helper_lkm/Makefile`
- `kernel/helper_lkm/build.sh`
- `kernel/helper_lkm/gds_helper_lkm.c`
- `kernel/helper_lkm/gds_helper_lkm.h`
- `kernel/kaslr-prefetch.c`
- `kernel/kaslr-sidt.c`
- `kernel/ktrigger.c`
- `kernel/matrix.sh`
- `kernel/reconstruct.sh`
- `kernel/reload.sh`
- `spy/Makefile`
- `spy/devmem-probe.c`
- `spy/diag.sh`
- `spy/run.sh`
- `spy/spy-victim.c`
- `spy/spy.h`
- `LICENSE_SCOPE.md`

## Files retaining their existing upstream or unresolved terms

- `downfall-oneshot.c`
- `downfall.S`
- `spy/sampler.S`
- `spy/spy.c`

The Downfall-derived files listed above retain their existing attribution to Daniel Moghimi and the upstream project. Its missing repository-wide license is not replaced by this declaration. The helper module and its interface already carried GPL-2.0 identifiers; these are now explicitly GPL-2.0-only.
