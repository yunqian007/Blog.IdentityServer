using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Blog.IdentityServer4.Data;
using Blog.IdentityServer4.Extension;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NLog.Config;

namespace Blog.IdentityServer4
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // 生成承载 web 应用程序的 Microsoft.AspNetCore.Hosting.IWebHost。
            // Build是WebHostBuilder最终的目的，将返回一个构造的WebHost，最终生成宿主。
            var host = CreateHostBuilder(args).Build();

            var config = new LoggingConfiguration();


            var logger = NLog.LogManager.GetCurrentClassLogger();
            logger.Info("Error occured seeding the Database.");

            #region 生成种子数据
            // 创建可用于解析作用域服务的新 Microsoft.Extensions.DependencyInjection.IServiceScope。
            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                try
                {
                    // 从 system.IServicec提供程序获取 T 类型的服务。
                    var configuration = services.GetRequiredService<IConfiguration>();
                    if (configuration.GetSection("AppSettings")["SeedDBDataEnabled"].ObjToBool())
                    {
                        SeedData.EnsureSeedData(host.Services);
                    }
                }
                catch (Exception e)
                {
                    //var logger = NLog.LogManager.GetCurrentClassLogger();
                    logger.Info(e, "Error occured seeding the Database.");
                }
            }

            #endregion


            // 运行 web 应用程序并阻止调用线程, 直到主机关闭。
            // 创建完 WebHost 之后，便调用它的 Run 方法，而 Run 方法会去调用 WebHost 的 StartAsync 方法
            // 将Initialize方法创建的Application管道传入以供处理消息
            // 执行HostedServiceExecutor.StartAsync方法
            host.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder
                    .UseUrls("http://*:7005")
                    .UseStartup<Startup>();
                });
    }
}
