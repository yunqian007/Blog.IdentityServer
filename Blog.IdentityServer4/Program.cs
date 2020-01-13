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
            // ���ɳ��� web Ӧ�ó���� Microsoft.AspNetCore.Hosting.IWebHost��
            // Build��WebHostBuilder���յ�Ŀ�ģ�������һ�������WebHost����������������
            var host = CreateHostBuilder(args).Build();

            var config = new LoggingConfiguration();


            var logger = NLog.LogManager.GetCurrentClassLogger();
            logger.Info("Error occured seeding the Database.");

            #region ������������
            // ���������ڽ��������������� Microsoft.Extensions.DependencyInjection.IServiceScope��
            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                try
                {
                    // �� system.IServicec�ṩ�����ȡ T ���͵ķ���
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


            // ���� web Ӧ�ó�����ֹ�����߳�, ֱ�������رա�
            // ������ WebHost ֮�󣬱�������� Run �������� Run ������ȥ���� WebHost �� StartAsync ����
            // ��Initialize����������Application�ܵ������Թ�������Ϣ
            // ִ��HostedServiceExecutor.StartAsync����
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
