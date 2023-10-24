# SPN_Linear_Attack

## 运行程序

```bash
mkdir -p build && cd build
cmake ..
make
```

## 攻击思路

见./doc/tutorial.md

## 注意

攻击具有一定的成功概率

且正如原论文作者数据，在 10000 个明密文对下，会很大概率达到期望偏差 $1 / 32 = 0.03125$