// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using Microsoft.Owin.Security;
using Weibo;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="WeiboAuthenticationMiddleware"/>
    /// </summary>
    public static class WeiboAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Weibo
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseWeiboAuthentication(this IAppBuilder app, WeiboAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(WeiboAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using Weibo
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The appId assigned by Weibo</param>
        /// <param name="appSecret">The appSecret assigned by Weibo</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseWeiboAuthentication(
            this IAppBuilder app,
            string appId,
            string appSecret)
        {
            return UseWeiboAuthentication(
                app,
                new WeiboAuthenticationOptions
                {
                    AppId = appId,
                    AppSecret = appSecret,
                });
        }
    }
}
