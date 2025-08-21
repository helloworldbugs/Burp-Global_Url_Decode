# -*- coding: utf-8 -*-
from burp import IBurpExtender, IProxyListener
from java.net import URLDecoder

class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Global URL Decoder")
        callbacks.registerProxyListener(self)
        callbacks.printOutput("[*] Global URL Decoder Loading successfully")

    def processProxyMessage(self, messageIsRequest, message):
        info = message.getMessageInfo()
        try:
            if messageIsRequest:    # 改写请求包
                # return            # 跳过，不改写请求包
                raw = info.getRequest()
                decoded = self.decode_bytes(raw)
                info.setRequest(decoded)
            else:
                raw = info.getResponse()    # 改写响应包
                if raw:
                    decoded = self.decode_bytes(raw)
                    info.setResponse(decoded)
        except Exception as e:
            self._callbacks.printError("解码失败: {}".format(e))

    def decode_bytes(self, byte_array):
        # 将 byte[] 转成 str
        text = self._helpers.bytesToString(byte_array)

        # 避免 '+' 被当作空格
        safe_text = text.replace("+", "%2B")

        # URL 解码
        decoded_text = URLDecoder.decode(safe_text, "UTF-8")

        # 转回 byte[]
        return self._helpers.stringToBytes(decoded_text)
