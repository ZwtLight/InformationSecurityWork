# T1_tests.py
# 交互式测试脚本，便于课堂演示逐项运行第1~5关
# 在命令行下运行： python3 T1_tests.py
# 根据提示选择要运行的测试项，脚本会打印结果与耗时，并可要求保存到文件。

from T1_SDES import SDES
import time
import csv
from typing import List, Tuple


def menu():
    print("====== S-DES 交互式测试（课堂演示） ======")
    print("1) 第1关：基本加/解密示例")
    print("2) 第2关：交叉测试说明与示例")
    print("3) 第3关：ASCII 模式演示")
    print("4) 第4关：暴力破解演示（单对 / 多对）")
    print("5) 第5关：碰撞分析（统计并导出 CSV）")
    print("6) 退出")
    choice = input("请选择操作 (1-6): ").strip()
    return choice


def basic_demo(sdes: SDES):
    print("\n-- 第1关：基本加/解密 --")
    plaintext = input("请输入 8-bit 明文（默认 10110101）: ").strip() or "10110101"
    key = input("请输入 10-bit 密钥（默认 1010000010）: ").strip() or "1010000010"
    t0 = time.perf_counter()
    cipher = sdes.encrypt(plaintext, key)
    t1 = time.perf_counter()
    print(f"加密耗时: {t1 - t0:.6f} 秒, 密文 = {cipher}")
    print("加密过程日志:")
    print(sdes.get_log())
    t2 = time.perf_counter()
    recovered = sdes.decrypt(cipher, key)
    t3 = time.perf_counter()
    print(f"解密耗时: {t3 - t2:.6f} 秒, 解密结果 = {recovered}")
    print("解密过程日志:")
    print(sdes.get_log())
    print(f"明文与解密结果一致？ {recovered == plaintext}")


def cross_demo(sdes: SDES):
    print("\n-- 第2关：交叉测试说明与示例 --")
    print("交叉测试通常在两台不同设备上运行：A、B 使用相同算法和密钥 K。")
    plaintext = input("示例明文（8-bit，默认 10110101）: ").strip() or "10110101"
    key = input("示例密钥（10-bit，默认 1010000010）: ").strip() or "1010000010"
    c = sdes.encrypt(plaintext, key)
    print(f"A 端加密得到 C = {c}")
    recovered = sdes.decrypt(c, key)
    print(f"B 端解密得到 P = {recovered}")
    print(f"是否一致: {recovered == plaintext}")
    print("课堂演示提示：将生成的 C 与另一台运行相同代码的机器交叉验证。" )


def ascii_demo(sdes: SDES):
    print("\n-- 第3关：ASCII 模式演示 --")
    text = input("请输入 ASCII 明文（默认 'Hello!'）: ").strip() or "Hello!"
    key = input("请输入 10-bit 密钥（默认 1010000010）: ").strip() or "1010000010"
    t0 = time.perf_counter()
    blocks = sdes.encrypt_ascii_to_bitblocks(text, key)
    t1 = time.perf_counter()
    print(f"加密耗时: {t1 - t0:.6f} 秒")
    print("每字节对应的 8-bit 密文块（逗号分隔）:")
    print(", ".join(blocks))
    recovered = sdes.decrypt_bitblocks_to_ascii(blocks, key)
    print("解密还原 ASCII:", recovered)
    print("与原始一致？", recovered == text)


def bruteforce_demo(sdes: SDES):
    print("\n-- 第4关：暴力破解演示 --")
    num_pairs = int(input("请输入已知明密文对数目 (1 或 >=2 推荐，输入1表示单对): ").strip() or "1")
    pairs: List[Tuple[str, str]] = []
    for i in range(num_pairs):
        p = input(f"第{i+1}对 明文 (8-bit)，默认 10110101: ").strip() or "10110101"
        c = input(f"第{i+1}对 密文 (8-bit)，若留空程序会用默认密钥生成: ").strip()
        if not c:
            # 若未提供密文则生成（提示）
            key_for_gen = input("为生成示例密文请输入密钥（10-bit），默认 1010000010: ").strip() or "1010000010"
            c = sdes.encrypt(p, key_for_gen)
            print(f"生成的密文: {c} （使用密钥 {key_for_gen}）")
        pairs.append((p, c))

    use_threads = input("是否启用多线程加速? (y/n, 默认 y): ").strip().lower() != 'n'
    max_workers = int(input("并行线程数 (默认 8): ").strip() or "8")

    print("开始暴力破解（遍历 1024 个密钥）...")
    t0 = time.perf_counter()
    if len(pairs) == 1:
        matches, elapsed = sdes.brute_force_search_single_pair(pairs[0][0], pairs[0][1], use_threads=use_threads,
                                                               max_workers=max_workers)
    else:
        matches, elapsed = sdes.brute_force_search_multiple_pairs(pairs, use_threads=use_threads,
                                                                  max_workers=max_workers)
    t1 = time.perf_counter()
    print(f"暴力破解完成（脚本计时 {t1 - t0:.6f} 秒；内部返回耗时 {elapsed:.6f} 秒）")
    print(f"匹配密钥数: {len(matches)}")
    if matches:
        print("前 20 个候选密钥（若更多则只显示 20）:")
        for k in matches[:20]:
            print(k)
        save = input("是否导出候选密钥到 CSV 文件? (y/n): ").strip().lower() == 'y'
        if save:
            path = input("输入保存文件名（默认 bruteforce_candidates.csv）: ").strip() or "bruteforce_candidates.csv"
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['candidate_key_10bit'])
                for k in matches:
                    writer.writerow([k])
            print(f"已保存到 {path}")


def collision_demo(sdes: SDES):
    print("\n-- 第5关：碰撞分析 --")
    p = input("请输入要分析的明文 (8-bit，默认 10110101): ").strip() or "10110101"
    t0 = time.perf_counter()
    collisions = sdes.analyze_collision_for_plaintext(p)
    t1 = time.perf_counter()
    print(f"分析完成，耗时 {t1 - t0:.6f} 秒。找到 {len(collisions)} 个密文由多个密钥产生。")
    # 打印部分结果
    printed = 0
    for c, keys in collisions.items():
        print(f"{c} -> {len(keys)} keys, 示例 keys: {keys[:10]}")
        printed += 1
        if printed >= 10:
            break
    save = input("是否导出完整碰撞结果为 CSV? (y/n): ").strip().lower() == 'y'
    if save:
        path = input("输入保存文件名（默认 collision_results.csv）: ").strip() or "collision_results.csv"
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['ciphertext_8bit', 'num_keys', 'example_keys'])
            for c, keys in collisions.items():
                w.writerow([c, len(keys), ";".join(keys[:20])])
        print(f"已保存到 {path}")


def main():
    sdes = SDES()
    while True:
        choice = menu()
        if choice == '1':
            basic_demo(sdes)
        elif choice == '2':
            cross_demo(sdes)
        elif choice == '3':
            ascii_demo(sdes)
        elif choice == '4':
            bruteforce_demo(sdes)
        elif choice == '5':
            collision_demo(sdes)
        elif choice == '6':
            print("退出。")
            break
        else:
            print("无效选择，请重试。")
        input("\n按回车返回主菜单...")


if __name__ == "__main__":
    main()
