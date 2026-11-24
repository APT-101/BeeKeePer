"use client";

import * as React from "react";

// 语法高亮代码块（纯正则 tokenizer，无外部高亮库依赖）。
// 从 PoC 查看器抽出为共享组件：固件反编译页用它渲染 .c 伪代码，
// tokenHint 让命中的函数名可点击跳转（ARTEX-IOT 移植）。

type TokClass = "comment" | "string" | "number" | "keyword" | "func" | "punct" | "plain";
type Tok = { cls: TokClass; text: string };
type Lang = "py" | "sh" | "c" | "js" | "rb" | "http" | "text";

const KEYWORDS: Record<Lang, string[]> = {
  py: "def class return if elif else for while in not and or import from as with try except finally raise pass break continue lambda yield global nonlocal assert del None True False async await".split(
    " ",
  ),
  sh: "if then else elif fi for while do done case esac function return export local readonly set unset shift exit echo printf cd curl wget nc ncat base64".split(
    " ",
  ),
  c: "int char void unsigned signed long short float double struct union enum typedef static const extern return if else for while do switch case break continue sizeof goto NULL include define".split(
    " ",
  ),
  js: "const let var function return if else for while do switch case break continue new class extends import from export default async await try catch finally throw typeof null undefined true false".split(
    " ",
  ),
  rb: "def end class module require return if elsif else unless while until do each puts print begin rescue ensure raise nil true false".split(
    " ",
  ),
  http: "GET POST PUT DELETE PATCH HEAD OPTIONS HTTP HTTPS".split(" "),
  text: [],
};

function langOf(name: string): Lang {
  const ext = (name.split(".").pop() || "").toLowerCase();
  if (ext === "py") return "py";
  if (ext === "sh") return "sh";
  if (ext === "c" || ext === "h") return "c";
  if (ext === "js") return "js";
  if (ext === "rb") return "rb";
  if (ext === "http") return "http";
  return "text";
}

const TOKEN_RE = new RegExp(
  String.raw`(#[^\n]*|\/\/[^\n]*|\/\*[\s\S]*?\*\/)` +
    String.raw`|("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')` +
    String.raw`|(\b\d[\d._]*\b)` +
    String.raw`|([A-Za-z_][A-Za-z0-9_]*)` +
    String.raw`|(\s+)` +
    String.raw`|([\s\S])`,
  "g",
);

function tokenize(code: string, lang: Lang): Tok[][] {
  const kw = new Set(KEYWORDS[lang]);
  const lines: Tok[][] = [[]];
  const push = (cls: TokClass, text: string) => {
    const parts = text.split("\n");
    parts.forEach((part, i) => {
      if (i > 0) lines.push([]);
      if (part !== "") lines[lines.length - 1].push({ cls, text: part });
    });
  };
  TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TOKEN_RE.exec(code))) {
    if (m[1]) {
      // C 的 #define/#include 是预处理指令，不当注释
      push(lang === "c" && m[1].startsWith("#") ? "keyword" : "comment", m[0]);
    } else if (m[2]) {
      push("string", m[0]);
    } else if (m[3]) {
      push("number", m[0]);
    } else if (m[4]) {
      if (kw.has(m[4])) push("keyword", m[0]);
      else if (code[TOKEN_RE.lastIndex] === "(") push("func", m[0]);
      else push("plain", m[0]);
    } else if (m[5]) {
      push("plain", m[0]);
    } else {
      push("punct", m[0]);
    }
  }
  return lines;
}

const TOK_CLASS: Record<TokClass, string> = {
  comment: "text-muted-foreground/70 italic",
  string: "text-emerald-600 dark:text-emerald-400",
  number: "text-amber-600 dark:text-amber-400",
  keyword: "text-violet-600 dark:text-violet-400 font-medium",
  func: "text-sky-600 dark:text-sky-400",
  punct: "text-muted-foreground",
  plain: "text-foreground",
};

const LANG_LABEL: Record<Lang, string> = {
  py: "Python",
  sh: "Shell",
  c: "C",
  js: "JavaScript",
  rb: "Ruby",
  http: "HTTP",
  text: "Text",
};

export function HighlightedCode({
  code,
  name,
  tokenHint,
}: {
  code: string;
  name: string;
  /** 可选：给命中的标识符追加样式（反编译页用它把可跳转函数打成手型光标）。 */
  tokenHint?: (text: string) => string | undefined;
}) {
  const lang = langOf(name);
  const lines = React.useMemo(() => tokenize(code, lang), [code, lang]);
  return (
    <div className="overflow-hidden rounded-lg border shadow-sm">
      <div className="bg-muted/50 text-muted-foreground flex items-center justify-between border-b px-3 py-1.5 text-[11px]">
        <span className="flex items-center gap-2">
          <span className="size-2 rounded-full bg-emerald-500/70" />
          <span className="font-mono tracking-wide">{LANG_LABEL[lang]}</span>
        </span>
        <span className="tabular-nums">{lines.length} 行</span>
      </div>
      <div className="bg-card overflow-x-auto">
        <pre className="font-mono text-xs leading-6">
          <code>
            {lines.map((toks, i) => (
              <div key={i} className="hover:bg-muted/40 flex min-h-6">
                <span className="bg-muted/30 text-muted-foreground/50 w-12 shrink-0 select-none border-r px-2 text-right tabular-nums">
                  {i + 1}
                </span>
                <span className="flex-1 whitespace-pre-wrap break-all pr-4 pl-3">
                  {toks.length === 0
                    ? " "
                    : toks.map((t, j) => (
                        <span
                          key={j}
                          className={`${TOK_CLASS[t.cls]} ${tokenHint?.(t.text) ?? ""}`}
                        >
                          {t.text}
                        </span>
                      ))}
                </span>
              </div>
            ))}
          </code>
        </pre>
      </div>
    </div>
  );
}

// ---------------- 关联漏洞 ----------------
