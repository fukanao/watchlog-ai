# watchlog-ai

AI-powered log watcher for detecting suspicious activity in web server access and error logs.

## 目的

`access.log` と `error.log` の新規行を 5 分ごとに確認し、Ollama の生成AIで危険度を判定します。
危険度が「高」または「中」の場合だけ Slack、メール、Raspberry Pi などの webhook に通知します。

危険度の意味:

- 高: いますぐ対応が必要。脆弱性を突かれた、または情報が漏洩した。
- 中: 攻撃検知。回数が多い、または攻撃らしいが情報漏洩は確認できない。
- 低: スキャン程度。
- 無: 正常アクセス。

## 開発環境で試す

```bash
cp .env.example .env
python3 -m watchlog_ai --once
```

開発時のログは `logs/access.log` と `logs/error.log` を読みます。
通知テストだけしたい場合は `.env` の `DRY_RUN=true` にすると、通知本文を標準出力に表示します。

## Ubuntu への配置例

```bash
sudo useradd --system --home /opt/watchlog-ai --shell /usr/sbin/nologin watchlog-ai
sudo mkdir -p /opt/watchlog-ai
sudo rsync -a ./ /opt/watchlog-ai/
sudo chown -R watchlog-ai:watchlog-ai /opt/watchlog-ai
sudo -u watchlog-ai python3 -m venv /opt/watchlog-ai/.venv
sudo -u watchlog-ai /opt/watchlog-ai/.venv/bin/pip install -r /opt/watchlog-ai/requirements.txt
sudo cp /opt/watchlog-ai/.env.example /opt/watchlog-ai/.env
sudoedit /opt/watchlog-ai/.env
sudo cp /opt/watchlog-ai/deploy/watchlog-ai.service /etc/systemd/system/watchlog-ai.service
sudo systemctl daemon-reload
sudo systemctl enable --now watchlog-ai
```

本番では `.env` を次のように変更します。

```dotenv
LOG_DIR=/var/log/znw-support-ai-flask
START_AT_END=true
OLLAMA_URL=http://10.0.4.101:11534
OLLAMA_MODEL=gpt-oss:120b
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

`START_AT_END=true` にすると初回起動時は既存ログを通知せず、起動後に追記された新規ログだけを判定します。
`watchlog-ai` ユーザーがログを読めない場合は、Ubuntu 側で次のように読み取り権限を付与してください。

```bash
sudo setfacl -m u:watchlog-ai:rX /var/log/znw-support-ai-flask
```

## 主な設定

- `OLLAMA_URL`: Ollama のURL。例: `http://10.0.4.101:11534`
- `OLLAMA_MODEL`: 使用モデル。例: `gpt-oss:120b`
- `SLACK_WEBHOOK_URL`: Slack Incoming Webhook URL
- `RASPI_WEBHOOK_URL`: Raspberry Pi 側などで受ける任意の webhook URL
- `EMAIL_ENABLED`: メール通知を使う場合は `true`
- `LOG_DIR`: 監視対象ログのディレクトリ
- `CHECK_INTERVAL_SECONDS`: 監視間隔。標準は `300`
- `STATE_FILE`: 読み取り位置を保存するJSONファイル

## 実行コマンド

1 回だけチェック:

```bash
python3 -m watchlog_ai --once
```

常駐実行:

```bash
python3 -m watchlog_ai
```
