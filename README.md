## 关于

csv-attestation 是海光 [csv attestation sdk](https://gitee.com/anolis/hygon-devkit/tree/master/csv/attestation) (C语言)
的 Golang 库.

## 功能

- [X] 用户态生成报告 ioctl_get_attestation
- [ ] 内核态生成报告 vmmcall_get_attestation
- [X] 验证报告 verify_attestation

## 其他

Python 版本实现 (by 阿里云):

- [requirements.txt](https://enclave-cn-hangzhou.oss-cn-hangzhou.aliyuncs.com/csv/requirements.txt)
- [csv-attestation.py](https://enclave-cn-hangzhou.oss-cn-hangzhou.aliyuncs.com/csv/csv-attestation.py)
