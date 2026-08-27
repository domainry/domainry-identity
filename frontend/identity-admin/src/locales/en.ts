import type { MessageKey } from "./zh-CN";
import coreMessages from "./en/core";
import identityMessages from "./en/identity";

const messages: Record<MessageKey, string> = {
  ...coreMessages,
  ...identityMessages,
};

export default messages;
