English | [中文](#中文)

# Privacy guard

`privacy_scan.py` keeps personal data out of this public repository: LAN addresses, home paths, emails, credentials and image-generation metadata. Python 3.9+, standard library only. It never prints a matched value; a finding is one line, `location: rule_id -- why`.

## Set up (once per clone)

```sh
git config core.hooksPath .githooks
git config user.email "<id>+<name>@users.noreply.github.com"   # the hooks reject any other address
python3 tools/privacy_scan.py --tracked --history              # expect: clean
```

`pre-commit` runs `--identity --staged`, `commit-msg` runs `--message "$1"`, `pre-push` runs `--history`. CI runs `--no-private --tracked --history` on every push to `main` and every pull request.

## Modes

Combine them freely. `PATH` may be a file or a directory (recursive, `.git` skipped).

| Flag | Scans |
| --- | --- |
| `--staged` | the index: what the next commit will contain |
| `--tracked` | every tracked file as it is in the working tree |
| `--history` | every blob, commit and tag reachable from any ref, plus author, committer and tagger emails and messages |
| `--identity` | the email in `GIT_AUTHOR_IDENT` and `GIT_COMMITTER_IDENT` must match `allowed_emails` |
| `--message FILE` | a commit message file; lines starting with `#` are ignored |
| `--rules FILE` | use another public rules file |
| `--no-private` | do not load the private rules |

Exit status: `0` clean, `1` findings, `2` usage or internal error. Locations look like `docs/a.md:12`, `blob 1a2b3c4d5e6f docs/a.md:12` (history), `commit 1a2b3c4d5e6f author:1` or `message:3` (annotated tags say `tag`), and `identity author:1`. Images report line 1. The guard fails closed: a file it cannot read or decode is a finding.

## Rules

| Rule id | Catches |
| --- | --- |
| `lan_ip` | private, CGNAT (100.64/10) and link-local IPv4; IPv6 unique-local and link-local |
| `ipv4_address` | any other dotted quad; documentation ranges pass |
| `home_path` | `/Users/<name>`, `/home/<name>`, `~<name>/`; placeholders (`you`, `user`, `me`, `example`, `runner`, `shared`) pass |
| `windows_user_path` | `X:\Users\<name>`; `Public`, `Default` and placeholders pass |
| `email` | any address except noreply, `@example.com/org/net` and `git@github.com` |
| `credential_shape` | GitHub, Anthropic, OpenAI-style, Hugging Face, AWS, Slack and Google keys, private key headers, JWTs, and `key = long-token` assignments |
| `mac_address` | six hex pairs joined by `:` or `-` |
| `tunnel_host` | hosts under ts.net, trycloudflare.com, cfargotunnel.com and ngrok |
| `lan_hostname` | `<name>.local`, `.lan`, `.internal`, `.home.arpa` |
| `generation_metadata` | PNG text chunks `prompt`, `workflow`, `parameters`, `Comment`, `Description`, or a ComfyUI graph; raw-byte check for JPEG, WEBP, GIF |
| `binary_not_allowed` | a file with NUL bytes whose suffix is not in `allowed_binary_suffixes` |
| `undecodable` | a file that is not valid UTF-8, or a file, PNG chunk or git object that cannot be read or parsed |

Author, committer and tagger emails (`--identity`, `--history`) face a stricter test than `email`: only `allowed_emails` patterns pass.

## Private rules

Your own patterns (names, handles, machine names) live outside the repository in `~/.config/agent-genops/private_rules.json`, or in the file named by `AGENT_GENOPS_PRIVATE_RULES`. The schema is the one in `tools/privacy_rules.json`, and every list is appended to the public one. A line on stderr says how many private rules loaded. `AGENT_GENOPS_REQUIRE_PRIVATE=1` turns a missing file into an error (exit 2).

```json
{
  "version": 1,
  "rules": [{"id": "my_handle", "pattern": "\\bmy-handle\\b", "flags": "i", "why": "account handle"}],
  "allow_literals": ["build-box"],
  "allow_patterns": [],
  "allowed_emails": ["^me@example\\.org$"],
  "allowed_binary_suffixes": []
}
```

`version` is required and `note` is free text that is ignored; any other unknown key is an error, so a typo cannot silently drop rules. `flags` is optional (`i` only). `suffixes` optionally limits a rule to file types such as `[".md"]`. Before a line is matched, every `allow_literals` entry (as a whole token, so `0.0.0.0` never hides a longer address) and every `allow_patterns` match is replaced by spaces. Fix a false positive by adding an entry there, not by weakening the public rules.

## Limits

- Pattern based: base64, URL-encoded or split-up values are not decoded.
- File names are not scanned and pixel data is not inspected, so keep generated images out of the repository.
- JPEG, WEBP and GIF are scanned as raw bytes; a large photo can rarely trip a rule by chance.
- `--history` stops on a shallow clone (exit 2); run `git fetch --unshallow` first.
- With `git commit -v` the diff shown in the editor is part of the message file and is scanned too.

## 中文

`privacy_scan.py` 在内容进入公开仓库之前拦下个人信息：内网地址、家目录路径、邮箱、凭据，以及图片里嵌入的生成元数据。只用 Python 3.9+ 标准库。命中的原文永远不会打印，每个问题只有一行：`位置: 规则 id -- 原因`。

### 初次设置（每个克隆做一次）

```sh
git config core.hooksPath .githooks
git config user.email "<id>+<name>@users.noreply.github.com"   # hook 只放行 noreply 邮箱
python3 tools/privacy_scan.py --tracked --history              # 应当输出 clean
```

`pre-commit` 运行 `--identity --staged`，`commit-msg` 运行 `--message "$1"`，`pre-push` 运行 `--history`。CI 在每次推送 `main` 和每个 pull request 时运行 `--no-private --tracked --history`。

### 参数

可以任意组合；`PATH` 可以是文件或目录（递归，跳过 `.git`）。

| 参数 | 扫描对象 |
| --- | --- |
| `--staged` | 暂存区，也就是下一次提交会包含的内容 |
| `--tracked` | 工作区里每个已跟踪的文件 |
| `--history` | 所有引用可达的 blob、提交和标签，外加作者、提交者、标签者的邮箱和提交说明 |
| `--identity` | `GIT_AUTHOR_IDENT` 和 `GIT_COMMITTER_IDENT` 里的邮箱必须匹配 `allowed_emails` |
| `--message FILE` | 一个提交说明文件，`#` 开头的行忽略 |
| `--rules FILE` | 换用另一份公开规则 |
| `--no-private` | 不加载私有规则 |

退出码：`0` 干净，`1` 有发现，`2` 用法错误或内部错误。位置写法见上面的英文部分，图片一律报第 1 行。宁可误报也不漏报：读不了或解不开的文件，本身就算一条发现。

### 规则

| 规则 id | 拦截内容 |
| --- | --- |
| `lan_ip` | 私有、CGNAT（100.64/10）和链路本地的 IPv4；IPv6 唯一本地和链路本地地址 |
| `ipv4_address` | 其他任何点分 IPv4；文档专用网段放行 |
| `home_path` | `/Users/<name>`、`/home/<name>`、`~<name>/`；`you`、`user`、`me`、`example`、`runner`、`shared` 这类占位名放行 |
| `windows_user_path` | `X:\Users\<name>`；`Public`、`Default` 和占位名放行 |
| `email` | 所有邮箱，noreply、`@example.com/org/net` 和 `git@github.com` 除外 |
| `credential_shape` | GitHub、Anthropic、OpenAI 风格、Hugging Face、AWS、Slack、Google 的密钥，私钥头，JWT，以及“密钥名 = 长令牌值”的赋值 |
| `mac_address` | 用 `:` 或 `-` 连接的六组十六进制 |
| `tunnel_host` | ts.net、trycloudflare.com、cfargotunnel.com、ngrok 下的主机名 |
| `lan_hostname` | `<name>.local`、`.lan`、`.internal`、`.home.arpa` |
| `generation_metadata` | PNG 文本块 `prompt`、`workflow`、`parameters`、`Comment`、`Description`，或 ComfyUI 节点图；JPEG、WEBP、GIF 查原始字节 |
| `binary_not_allowed` | 含 NUL 字节、后缀又不在 `allowed_binary_suffixes` 里的文件 |
| `undecodable` | 不是合法 UTF-8 的文件，或读不了、解析不了的文件、PNG 数据块、git 对象 |

作者、提交者和标签者的邮箱（`--identity`、`--history`）要过更严的一关：只有匹配 `allowed_emails` 的才放行。

### 私有规则

你自己的规则（姓名、账号、机器名）放在仓库之外的 `~/.config/agent-genops/private_rules.json`，也可以用环境变量 `AGENT_GENOPS_PRIVATE_RULES` 指向别的文件。格式与 `tools/privacy_rules.json` 相同，各个列表接在公开规则后面。stderr 上会有一行告诉你加载了多少条私有规则。设了 `AGENT_GENOPS_REQUIRE_PRIVATE=1`，文件不存在就报错退出（退出码 2）。上面英文部分有一个完整的示例。

`version` 必填，`note` 是会被忽略的备注；其余未知的键一律报错，免得拼错键名悄悄丢掉规则。`flags` 可省略（只支持 `i`）；`suffixes` 可以把一条规则限定在某些文件类型上，例如 `[".md"]`。每行匹配之前，`allow_literals` 里的每一项（按整词匹配，所以 `0.0.0.0` 不会遮住更长的地址）和 `allow_patterns` 的每处命中，都会被替换成等长的空格。遇到误报，往这两处加条目，不要去削弱公开规则。

### 局限

- 只做模式匹配：base64、URL 编码、被拆开的值都不会解码。
- 不检查文件名，也不检查像素数据，所以生成的图片不要放进仓库。
- JPEG、WEBP、GIF 按原始字节扫描，较大的照片偶尔会碰巧触发规则。
- 浅克隆上 `--history` 会直接报错退出（退出码 2），先执行 `git fetch --unshallow`。
- 用 `git commit -v` 时，编辑器里的 diff 也在提交说明文件里，会一起被扫描。
