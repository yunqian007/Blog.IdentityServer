using Blog.IdentityServer4.ConfigCenter;
using Blog.IdentityServer4.Helper;
using Blog.IdentityServer4.Model;
using Blog.IdentityServer4.Model.Bak;
using IdentityModel;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Blog.IdentityServer4.Data
{
    public class SeedData
    {
        public static void EnsureSeedData(IServiceProvider serviceProvider)
        {
            Console.WriteLine("Seeding database...");

            using (var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

                {
                    var context = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                    context.Database.Migrate();
                    EnsureSeedData(context);
                }

                {
                    var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
                    context.Database.Migrate();

                    var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                    var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

                    var BlogCore_Users = JsonHelper.ParseFormByJson<List<UserModel>>(GetTableData.GetData(nameof(UserModel)));
                    var BlogCore_Roles = JsonHelper.ParseFormByJson<List<RoleModel>>(GetTableData.GetData(nameof(RoleModel)));
                    var BlogCore_UserRoles = JsonHelper.ParseFormByJson<List<UserRoleModel>>(GetTableData.GetData(nameof(UserRoleModel)));

                    foreach (var user in BlogCore_Users)
                    {
                        if (user == null || user.LoginName == null)
                        {
                            continue;
                        }
                        var userItem = userMgr.FindByNameAsync(user.LoginName).Result;
                        var rid = BlogCore_UserRoles.FirstOrDefault(d => d.UserId == user.Id)?.RoleId;
                        var rName = BlogCore_Roles.Where(d => d.Id == rid).Select(d => d.Id).ToList();

                        if (userItem == null)
                        {
                            if (rid > 0 && rName.Count > 0)
                            {
                                userItem = new ApplicationUser
                                {
                                    UserName = user.UserName,
                                    LoginName = user.LoginName,
                                    Sex = user.Sex,
                                    Age = user.Age,
                                    Birthday = user.Brithday,
                                    Address = user.Address,
                                    IsDelete = user.IsDeleted

                                };

                                //var result = userMgr.CreateAsync(userItem, "BlogIdp123$" + item.uLoginPWD).Result;

                                // 因为导入的密码是 MD5密文，所以这里统一都用初始密码了
                                var pwdInit = "BlogIdp123$InitPwd";
                                //if (userItem.UserName== "blogadmin")
                                //{
                                //    pwdInit = "#InitPwd";
                                //}
                                var result = userMgr.CreateAsync(userItem, pwdInit).Result;
                                if (!result.Succeeded)
                                {
                                    throw new Exception(result.Errors.First().Description);
                                }

                                var claims = new List<Claim>{
                            new Claim(JwtClaimTypes.Name, user.UserName),
                            new Claim(JwtClaimTypes.Email, $"{user.LoginName}@email.com"),
                        };

                                claims.AddRange(rName.Select(s => new Claim(JwtClaimTypes.Role, s.ToString())));


                                result = userMgr.AddClaimsAsync(userItem, claims).Result;


                                if (!result.Succeeded)
                                {
                                    throw new Exception(result.Errors.First().Description);
                                }
                                Console.WriteLine($"{userItem?.UserName} created");//AspNetUserClaims 表

                            }
                            else
                            {
                                Console.WriteLine($"{user?.LoginName} doesn't have a corresponding role.");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"{userItem?.UserName} already exists");
                        }

                    }

                    // 迁移【角色】信息，Role信息统一在这里处理，Blog.Core 只负责读，不负责写
                    foreach (var item in BlogCore_Roles)
                    {
                        if (item == null || item.Name == null)
                        {
                            continue;
                        }

                        var roleModel = roleMgr.FindByNameAsync(item.Name).Result;

                        if (roleModel == null)
                        {
                            roleModel = new ApplicationRole
                            {
                                Name = item.Name,
                                Description = item.Description,
                                IsDeleted = (bool)(item.IsDeleted),
                                CreateBy = item.CreateBy,
                                CreateId = item.CreateId,
                                CreateTime = item.CreateTime,
                                ModifyBy = item.ModifyBy,
                                ModifyId = item.ModifyId,
                                ModifyTime = item.ModifyTime,
                                Enabled = item.Enabled,
                                OrderSort = item.OrderSort,
                                NormalizedName = item.Name,
                            };

                            var result = roleMgr.CreateAsync(roleModel).Result;
                            if (!result.Succeeded)
                            {
                                throw new Exception(result.Errors.First().Description);
                            }
                        }
                        else
                        {
                            Console.WriteLine($"{roleModel?.Name} already exists");
                        }

                    }

                }
            }

            Console.WriteLine("Done seeding database.");
            Console.WriteLine();
        }

        private static void EnsureSeedData(ConfigurationDbContext context)
        {
            if (!context.Clients.Any())
            {
                Console.WriteLine("Clients being populated");
                foreach (var client in IdentityServer4Config.GetClients().ToList())
                {
                    context.Clients.Add(client.ToEntity());
                }
                context.SaveChanges();
            }
            else
            {
                Console.WriteLine("Clients already populated");
            }

            if (!context.IdentityResources.Any())
            {
                Console.WriteLine("IdentityResources being populated");
                foreach (var resource in IdentityServer4Config.GetIdentityResources().ToList())
                {
                    context.IdentityResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }
            else
            {
                Console.WriteLine("IdentityResources already populated");
            }

            if (!context.ApiResources.Any())
            {
                Console.WriteLine("ApiResources being populated");
                foreach (var resource in IdentityServer4Config.GetApiResources().ToList())
                {
                    context.ApiResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }
            else
            {
                Console.WriteLine("ApiResources already populated");
            }
        }
    }
}
