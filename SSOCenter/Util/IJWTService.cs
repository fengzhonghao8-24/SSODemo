﻿using SSOCenter.Models;

namespace SSOCenter.Util
{
    /// <summary>
    /// JWT服务接口
    /// </summary>
    public interface IJWTService
    {
        /// <summary>
        /// 获取授权码
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        ResponseModel<string> GetCode(string clientId, string userName, string password);
        /// <summary>
        /// 根据会话Code获取授权码
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="sessionCode"></param>
        /// <returns></returns>
        ResponseModel<string> GetCodeBySessionCode(string clientId, string sessionCode);

        /// <summary>
        /// 根据授权码获取Token+RefreshToken
        /// </summary>
        /// <param name="authCode"></param>
        /// <returns>Token+RefreshToken</returns>
        ResponseModel<GetTokenDTO> GetTokenWithRefresh(string authCode);

        /// <summary>
        /// 根据RefreshToken刷新Token
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <param name="clientId"></param>
        /// <returns></returns>
        string GetTokenByRefresh(string refreshToken, string clientId);
    }
}
