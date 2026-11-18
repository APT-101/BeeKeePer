import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "BEEKEEPER",
  // 侧栏左上角字符 logo 的显示用短名（用户钦定；全名仍用于 title 等处）。
  shortName: "BEEGUARD",
  version: packageJson.version,
  copyright: `© ${currentYear}, BeeKeePer.`,
  meta: {
    title: "BEEKEEPER — 自主渗透测试控制台",
    description: "LLM 驱动的自主渗透测试系统控制台",
  },
};
