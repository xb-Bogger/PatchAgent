> [!NOTE]
> The original repository, primarily intended for research purposes, is located at [osf.io/8k2ac](https://osf.io/8k2ac). 
> This repository is a fork of the original repository, which is focused on real-world bug fixing.

# PatchAgent

[![Build Status](https://github.com/cla7aye15I4nd/PatchAgent/actions/workflows/push-to-ghcr.yaml/badge.svg)](https://github.com/cla7aye15I4nd/PatchAgent/actions/workflows/push-to-ghcr.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


PatchAgent is a LLM-based practical program repair agent that mimics human expertise. It is designed to automatically generate patches for real-world bugs. In essence, PatchAgent employs a language server, a patch verifier, and interaction optimization techniques to mimic human-like reasoning during vulnerability repair.

## Example

PatchAgent can used to repair real-world bugs. For example, the following code snippet can be used to repair oss-fuzz issue:

```python
from patchagent.builder import OSSFuzzBuilder
from patchagent.agent.generator import generic_agent_generator
from patchagent.task import PatchTask

patchtask = PatchTask(
    ["poc.bin"],
    "libpng_read_fuzzer",
    OSSFuzzBuilder(
        "libpng",
        "<path-to-libpng>",
        "<path-to-oss-fuzz>",
    ),
)

patchtask.repair(generic_agent_generator(patchtask))
```

## Fixed Bugs

This table is just a sample of the vulnerabilities fixed so far. We will unredact as responsible disclosure periods end.

| Repository | Stars | Vulnerabilities |
| - | - | - |
| [assimp](https://github.com/assimp/assimp) | 11.4k | [#5763](https://github.com/assimp/assimp/pull/5763), [#5764](https://github.com/assimp/assimp/pull/5764), [#5765](https://github.com/assimp/assimp/pull/5765) |
| [hdf5](https://github.com/HDFGroup/hdf5) | 0.6k | [#5201](https://github.com/HDFGroup/hdf5/pull/5201), [#5210](https://github.com/HDFGroup/hdf5/pull/5210) |
| [libredwg](https://github.com/LibreDWG/libredwg) | 1.0k | [#1061](https://github.com/LibreDWG/libredwg/pull/1061) |
| [Pcap++](https://github.com/seladb/PcapPlusPlus) | 2.8k | [#1678](https://github.com/seladb/PcapPlusPlus/pull/1678), [#1680](https://github.com/seladb/PcapPlusPlus/pull/1680) |

## Contact

Feel free to use GitHub issues and pull requests for improvements, bug fixes, and questions. For personal communication related to PatchAgent, please contact [Zheng Yu](https://www.dataisland.org).

## Reference

To cite PatchAgent in scientific publications, please use the following reference:

```bibtex
@article{PatchAgent,
  title     = {PatchAgent: A Practical Program Repair Agent Mimicking Human Expertise},
  author    = {Yu, Zheng and Guo, Ziyi and Wu, Yuhang and Yu, Jiahao and 
               Xu, Meng and Mu, Dongliang and Chen, Yan and Xing, Xinyu},
  booktitle = {34rd USENIX Security Symposium (USENIX Security 25)},
  year      = {2025}
}
```