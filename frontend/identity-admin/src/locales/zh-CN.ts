import coreMessages from "./zh-CN/core";
import identityMessages from "./zh-CN/identity";

const messages = {
  ...coreMessages,
  ...identityMessages,
} as const;

export type MessageKey = keyof typeof messages;

export default messages;
