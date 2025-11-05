# コンテンツ検証機能 - 動的更新機能

## 概要

名前付きパイプ（FIFO）を使用して、Pythonから`cefnetd`のコンテンツ検証用HashMapにオンデマンドでエントリを追加できる機能。

## アーキテクチャ

```
┌─────────────┐         ┌──────────────────┐
│   Python    │─(write)→│ Named FIFO       │
│   Script    │         │ /tmp/cefnetd_    │
└─────────────┘         │  verify.fifo     │
                        └──────────────────┘
                                 │
                                 │ (poll + read)
                                 ↓
                        ┌──────────────────┐
                        │    cefnetd       │
                        │  ┌────────────┐  │
                        │  │  HashMap   │  │
                        │  │ (verify)   │  │
                        │  └────────────┘  │
                        └──────────────────┘
```

### データフォーマット

FIFOに書き込むデータは以下のフォーマット：

```
[hashkey(32bytes)][data_len(4bytes)][data(variable)]
```

- **hashkey**: ペイロードのSHA256ハッシュ値（32バイト）
- **data_len**: パケット情報の長さ（4バイト、uint32_t）
- **data**: パケット情報（name:chunk_num 形式のバイナリデータ）

## 実装の詳細

### C側（cefnetd）

1. **初期化** (`cefnetd_handle_create`):
   - `/tmp/cefnetd_verify.fifo` を作成
   - 非ブロッキングモードで開く
   - `hdl->verify_pipe_fd` に保存

2. **ポーリング** (`cefnetd_poll_socket_prepare`):
   - `verify_pipe_fd` を poll 対象に追加

3. **データ読み込み** (`cefnetd_input_verify_update_process`):
   - FIFOからデータを読み込む
   - フォーマットを検証
   - `insert_hashmap()` でHashMapに追加

4. **終了処理** (`cefnetd_handle_destroy`):
   - FIFOを閉じて削除

### Python側

`content_verification_updater.py` が以下を提供：

- `add_verification_entry(payload, packet_info)`: エントリ追加関数
- `example_usage()`: サンプルデータでの実行例
- `interactive_mode()`: 対話的にエントリを追加

## 使い方

### 1. cefnetdの起動

```bash
# cefnetdを起動（FIFOが自動的に作成される）
sudo cefnetd
```

### 2. Pythonスクリプトでエントリ追加

#### 例1: サンプルデータの追加

```bash
python3 tools/content_verification_updater.py
```

#### 例2: 対話モード

```bash
python3 tools/content_verification_updater.py -i
```

#### 例3: 独自スクリプトから

```python
from content_verification_updater import add_verification_entry

# ペイロードとパケット情報を準備
payload = b"your content data"
packet_info = b"\x00\x01\x00\x06server\x00\x01\x00\x04file:0"

# エントリを追加
add_verification_entry(payload, packet_info)
```

## ログ確認

cefnetdのログで確認できる情報：

```
Initialization content verification HashMap ... OK
Created FIFO for content verification: /tmp/cefnetd_verify.fifo
Added new content verification entry (data_len=29)
```

コンテンツ検証時の詳細ログは `/tmp/content_verification.log` に出力される。

## トラブルシューティング

### FIFOが見つからない

```bash
# FIFOの存在確認
ls -l /tmp/cefnetd_verify.fifo
```

cefnetdが起動していない場合はFIFOが作成されていない。

### 書き込み権限エラー

```bash
# FIFOの権限確認
ls -l /tmp/cefnetd_verify.fifo

# 権限変更（必要に応じて）
sudo chmod 666 /tmp/cefnetd_verify.fifo
```

### データが追加されない

1. cefnetdのログを確認
2. `/tmp/content_verification.log` を確認
3. Pythonスクリプトのエラー出力を確認

## 利点と欠点

### 利点
- 実装がシンプル
- 既存のpollループに統合しやすい
- バイナリデータを確実に送受信できる
- プロセス間通信として信頼性が高い

### 欠点
- 一方向通信（応答が必要な場合は別途実装が必要）
- パイプのバッファサイズに制限がある
- 複数のPythonプロセスから同時書き込みする場合は排他制御が必要

## 今後の拡張案

1. **双方向通信**: 応答用のFIFOを追加
2. **エントリ削除**: 削除コマンドの実装
3. **一括追加**: 複数エントリを一度に追加
4. **統計情報**: エントリ数や検証成功率の取得
