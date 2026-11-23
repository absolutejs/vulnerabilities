/**
 * Where a JavaScript or TypeScript file holds text rather than code: string
 * literals, template text (not its `${}` expressions) and comments. A docs
 * page that shows `process.env.OPENAI_API_KEY` in a code sample is not page
 * code reading a secret, and checks that look at code use this to tell the
 * two apart. A small lexer, not a parser: regular expression literals can
 * confuse it, which only ever makes a check see slightly less.
 */

type LexMode = "block" | "code" | "double" | "line" | "single" | "template";

type Lexer = {
  braces: number;
  mode: LexMode;
  open: number;
  ranges: Array<[number, number]>;
  /* The brace depth each open `${` began at, innermost last. */
  templates: number[];
};

const enter = (lexer: Lexer, mode: LexMode, index: number) => {
  lexer.mode = mode;
  lexer.open = index;

  return 0;
};

const close = (lexer: Lexer, end: number) => {
  lexer.ranges.push([lexer.open, end]);
  lexer.mode = "code";

  return 0;
};

const COMMENT_CLOSE = "*/";
const OPENERS: Record<string, LexMode> = {
  "'": "single",
  '"': "double",
  "`": "template",
};

const stepCode = (
  lexer: Lexer,
  char: string,
  following: string,
  index: number,
) => {
  if (char === "/" && following === "/") return enter(lexer, "line", index);
  if (char === "/" && following === "*") return enter(lexer, "block", index);
  const opener = OPENERS[char];
  if (opener) return enter(lexer, opener, index);
  if (char === "{") lexer.braces += 1;
  if (char !== "}") return 0;
  if (lexer.templates[lexer.templates.length - 1] !== lexer.braces) {
    lexer.braces -= 1;

    return 0;
  }
  lexer.templates.pop();

  return enter(lexer, "template", index);
};

const stepQuoted = (
  lexer: Lexer,
  char: string,
  quote: string,
  index: number,
) => {
  if (char === "\\") return 1;
  // An unterminated string ends with its line.
  if (char === quote || char === "\n") return close(lexer, index + 1);

  return 0;
};

const stepTemplate = (
  lexer: Lexer,
  char: string,
  following: string,
  index: number,
) => {
  if (char === "\\") return 1;
  if (char === "`") return close(lexer, index + 1);
  if (char !== "$" || following !== "{") return 0;
  close(lexer, index);
  lexer.templates.push(lexer.braces);

  return 1;
};

const step = (lexer: Lexer, text: string, index: number) => {
  const char = text[index] ?? "";
  const following = text[index + 1] ?? "";
  if (lexer.mode === "code") return stepCode(lexer, char, following, index);
  if (lexer.mode === "single") return stepQuoted(lexer, char, "'", index);
  if (lexer.mode === "double") return stepQuoted(lexer, char, '"', index);
  if (lexer.mode === "template")
    return stepTemplate(lexer, char, following, index);
  if (lexer.mode === "line") return char === "\n" ? close(lexer, index) : 0;
  if (char === "*" && following === "/") {
    close(lexer, index + COMMENT_CLOSE.length);

    return 1;
  }

  return 0;
};

export const isInRanges = (ranges: Array<[number, number]>, index: number) =>
  ranges.some(([start, end]) => index >= start && index < end);
/** Ranges of `text` that are literal text or comments, in order. */
export const literalRanges = (text: string) => {
  const lexer: Lexer = {
    braces: 0,
    mode: "code",
    open: 0,
    ranges: [],
    templates: [],
  };
  for (let index = 0; index < text.length; index += 1)
    index += step(lexer, text, index);
  if (lexer.mode !== "code") lexer.ranges.push([lexer.open, text.length]);

  return lexer.ranges;
};
