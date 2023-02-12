using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Framework.Util
{
    /// <summary>
    /// JWT对称可逆加密
    /// 双方保存同一个密钥，签名速度快，但因为双方密钥一样，所以安全性比非对称加密低一些。
    /// </summary>
    public class JWTHSService : JWTBaseService
    {
        public JWTHSService(IOptions<AppSettingOptions> options, Cachelper cachelper) : base(options, cachelper)
        {

        }
        /// <summary>
        /// 生成对称加密签名凭证
        /// </summary>
        /// <param name="clientId"></param>
        /// <returns></returns>
        protected override SigningCredentials GetCreds(string clientId)
        {
            var appHSSettings = getAppInfoByAppKey(clientId);
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(appHSSettings.clientSecret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            return creds;
        }
        /// <summary>
        /// 根据appKey获取应用信息
        /// </summary>
        /// <param name="clientId"></param>
        /// <returns></returns>
        private AppHSSetting getAppInfoByAppKey(string clientId)
        {
            AppHSSetting appHSSetting = _appSettingOptions.Value.appHSSettings.Where(s => s.clientId == clientId).FirstOrDefault();
            return appHSSetting;
        }

    }
}
