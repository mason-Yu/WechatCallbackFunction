package demo;

import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.qq.weixin.mp.aes.WXBizMsgCrypt;

/**
 * 此处两个接口相同,一个是配置时用来验证的,一个是微信推送事件处理接口,注意一个是get请求, 一个是post请求
 * note: 此处必须是两个相同的接口名
 */
public class Program {
    @RequestMapping(value = "/loginByQRCode", method = RequestMethod.GET)
    @ApiOperation(value = "微信公众号基础配置url验证", notes = "用于配置回调接口之前的验证,参数"
            + "<div>[key ->signature 类型 string 微信加密签名</div>"
            + "<div>[key ->timeStamp 类型 string 时间戳</div>"
            + "<div>[key ->nonce 类型 string 随机数</div>"
            + "<div>[key ->echostr 类型 string 微信要求返回的数据</div>"
            + "返参"
            + "<div>[key ->echostr 类型 string 返回echostr</div>")
    public String checkSignature(@PathVariable String appkey, HttpServletRequest request, HttpServletResponse response) {
        // 微信加密签名
        String signature = request.getParameter("signature");
        // 时间戳
        String timeStamp = request.getParameter("timestamp");
        // 随机数
        String nonce = request.getParameter("nonce");
        // 微信要求返回的数据
        String echostr = request.getParameter("echostr");
        try {
            // 进行微信签名验证, 如果签名一样证明是微信接口调用
            String g_signature = generateSignature(timeStamp, nonce);
            if(g_signature.equals(signature)){
                return echostr;
            }
        } catch (AesException e) {
            logger.info("生成微信签名失败:" + e);
            e.printStackTrace();
        }

        return "";
    }

    @RequestMapping(value = "/loginByQRCode", method = RequestMethod.POST)
    @ApiOperation(value = "拿到微信用户信息", notes = "查询微信用户信息,参数"
            + "<xml>"
            + "<ToUserName><![CDATA[gh_fbe8a958756e]]></ToUserName>"
            + "<FromUserName><![CDATA[otAzGjrS4AYCmeJM1GhEOcHXXTAo]]></FromUserName>"
            + "<CreateTime>1433259128</CreateTime>"
            + "<MsgType><![CDATA[event]]></MsgType>"
            + "<Event><![CDATA[subscribe]]></Event>"
            + "<EventKey><![CDATA[scene|keystandard|keystr|extinfo]></EventKey>"
            + "</xml>"
            + "返参"
            + "<div>[key ->userId 类型 integer 返回用户id</div>")
    public String loginByQRCode(@PathVariable String appkey, HttpServletRequest request, HttpServletResponse response) {
        String resultStr = "";
        // 微信加密签名
        String msgSignature = request.getParameter("msg_signature");
        // 时间戳
        String timeStamp = request.getParameter("timestamp");
        // 随机数
        String nonce = request.getParameter("nonce");
        try {
            // 明文读取xml
            // Map<String, String> params = RequestUtil.parseXml(request);
            // 对于安全模式下的xml密码
            Map<String, String> params = parseDecryptXml(msgSignature, timeStamp, nonce, request);
            logger.info("进入大树保公众号回调事件返回信息:\n" + params);

            // 如果是event事件且event事件类型为subscribe则是新用户,需要进行用户信息入库
            if(Constant.EVENT.equalsIgnoreCase(params.get(Constant.MsgType))
                    && Constant.SUBSCRIBE.equalsIgnoreCase(params.get(Constant.EVENT))) {

                String openId = params.get(Constant.FromUserName);
                logger.info("有新用户关注公众号, 关注渠道:" + params.get(Constant.EventKey));

                String sceneId = "0"; // 设置默认关注渠道为0(无渠道)
                if(params.containsKey(Constant.EventKey) &&
                        !StringUtil.isEmpty(params.get(Constant.EventKey)) &&
                        params.get(Constant.EventKey).split("_").length > 1) {
                    sceneId = params.get(Constant.EventKey).split("_")[1];
                }

                //用户信息入库
                String surl = services_url + "/dsbservice/UserAdminAccountService/saveMpUser";
                Map<String, Object> uriVariables = new HashMap<String, Object>();
                uriVariables.put("openId", openId);
                uriVariables.put("sceneId", sceneId);
                uriVariables.put("appKey", appkey);
                ServiceMap sm = resttemplate.postForObject(surl, uriVariables,ServiceMap.class);
                if(sm.isSuccess()) {
                    logger.info("新用户关注大树保公众号成功");
                    // 返回加密的xml格式response
                    String toUserName = params.get(Constant.ToUserName);
                    return generateXml(toUserName, openId, timeStamp, nonce);
                } else {
                    logger.info("新用户关注大树保公众号成功, 信息入库失败");
                }
            }
        } catch (Exception e) {
            logger.error("解析微信回调参数失败, 用户信息未入库:" + e);
        }
        return resultStr;
    }

    public static String generateSignature(String timeStamp, String nonce) throws AesException{
        Properties prop = PropertiesConfigUtils.getWxProperties(DSB_APP_PATH);
        String token = prop.getProperty("wechat.mp.token");
        String signature = SHA1.getSHA1(token, timeStamp, nonce, "");
        return signature;

    }

    @SuppressWarnings("unchecked")
    public static Map<String, String> parseDecryptXml(String msgSignature,String timeStamp,String nonce,HttpServletRequest request) throws Exception {
        // 从request中取得输入流
        InputStream inputStream = request.getInputStream();
        BufferedInputStream bis = new BufferedInputStream(inputStream);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = bis.read(buffer)) > 0) {
            baos.write(buffer, 0, len);
        }
        byte[] bytes = baos.toByteArray();
        String body = new String(bytes);
        inputStream.close();
        // 创建加密类
        WXBizMsgCrypt wxcpt = getDsbMC();
        String respXml=wxcpt.decryptMsg(msgSignature, timeStamp, nonce, body);

        Map<String, String> map = new HashMap<>(6);
        // 将解密后的消息转为xml
        Document doc = DocumentHelper.parseText(respXml);
        Element rt = doc.getRootElement();
        List<Element> list = rt.elements();
        for (Element e : list) {
            map.put(e.getName(), e.getText());
        }
        return map;
    }

    public static String generateXml(String toUser,
                                     String fromUser,
                                     String timestamp,
                                     String nonce) throws Exception {

        String replyMsg = "<xml><ToUserName><![CDATA["+ toUser +"]]></ToUserName>"
                +"<FromUserName><![CDATA[" + fromUser + "]]></FromUserName>"
                +"<CreateTime>" + timestamp + "</CreateTime><MsgType><![CDATA[text]]></MsgType>"
                +"<Content><![CDATA[welcome]]></Content></xml>";

        // 对返回信息进行加密
        WXBizMsgCrypt pc = getDsbMC();
        String resultXML = pc.encryptMsg(replyMsg, timestamp, nonce);
        return resultXML;

    }

    public static WXBizMsgCrypt getDsbMC() {
        WXBizMsgCrypt wxcpt = null;
        try {
            Properties prop = PropertiesConfigUtils.getWxProperties(DSB_APP_PATH);
            String token = prop.getProperty("wechat.mp.token");
            String aesKey = prop.getProperty("wechat.mp.aesKey");
            String appId = prop.getProperty("wechat.pay.appId");
            // 创建加密类
            wxcpt = new WXBizMsgCrypt(token, aesKey, appId);
        } catch (AesException e) {
            e.printStackTrace();
        }
        return wxcpt;
    }
}
