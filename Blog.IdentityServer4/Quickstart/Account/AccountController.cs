// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Blog.IdentityServer4.Model;
using Blog.IdentityServer4.Quickstart.Account;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer4.Quickstart.UI
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [SecurityHeaders]
    //[AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events)
        {
            // if the TestUserStore is not in DI, then we'll just use the global users collection
            // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
            //_users = users ?? new TestUserStore(TestUsers.Users);
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;

            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
        }

        #region 01，Identity Server 4 登陆页面+async Task<IActionResult> Login(string returnUrl)
        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }
        #endregion

        #region 02，Identity Server 4 用户登陆操作+async Task<IActionResult> Login(LoginInputModel model, string button)
        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (await _clientStore.IsPkceClientAsync(context.ClientId))
                    {
                        // if the client is PKCE then we assume it's native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.Username);


                if (user!=null&&!user.IsDelete)
                {
                    var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(), user.UserName));

                        // make sure the returnUrl is still valid, and if so redirect back to authorize endpoint or a local page
                        // the IsLocalUrl check is only necessary if you want to support additional local pages, otherwise IsValidReturnUrl is more strict
                        if (_interaction.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
                        {
                            return Redirect(model.ReturnUrl);
                        }

                        return Redirect("~/");
                    }
                }


                //validate username/password against in-memory store
                #region validate username/password against in-memory store
                //if (_users.ValidateCredentials(model.Username, model.Password))
                //{
                //    var user = _users.FindByUsername(model.Username);
                //    await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.ClientId));

                //    // only set explicit expiration here if user chooses "remember me". 
                //    // otherwise we rely upon expiration configured in cookie middleware.
                //    AuthenticationProperties props = null;
                //    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                //    {
                //        props = new AuthenticationProperties
                //        {
                //            IsPersistent = true,
                //            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                //        };
                //    };

                //    // issue authentication cookie with subject ID and username
                //    var isuser = new IdentityServerUser(user.SubjectId)
                //    {
                //        DisplayName = user.Username
                //    };

                //    await HttpContext.SignInAsync(isuser, props);

                //    if (context != null)
                //    {
                //        if (await _clientStore.IsPkceClientAsync(context.ClientId))
                //        {
                //            // if the client is PKCE then we assume it's native, so this change in how to
                //            // return the response is for better UX for the end user.
                //            return this.LoadingPage("Redirect", model.ReturnUrl);
                //        }

                //        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                //        return Redirect(model.ReturnUrl);
                //    }

                //    // request for a local page
                //    if (Url.IsLocalUrl(model.ReturnUrl))
                //    {
                //        return Redirect(model.ReturnUrl);
                //    }
                //    else if (string.IsNullOrEmpty(model.ReturnUrl))
                //    {
                //        return Redirect("~/");
                //    }
                //    else
                //    {
                //        // user might have clicked on a malicious link - should be logged
                //        throw new Exception("invalid return URL");
                //    }
                //} /**/
                #endregion

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }
        #endregion

        #region 03，Identity Server 4 退出页面+async Task<IActionResult> Logout(string logoutId)
        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }
        #endregion

        #region 04，Identity Server 4 点击退出操作+async Task<IActionResult> Logout(LogoutInputModel model)
        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                //await HttpContext.SignOutAsync();


                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }
        #endregion

        #region 05，Identity Server 4 用户管理首页+IActionResult Users(string returnUrl = null)
        [HttpGet]
        [Route("Account/Users")]
        [Authorize]
        public IActionResult Users(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            var users = _userManager.Users.Where(d => !d.IsDelete).OrderBy(d => d.UserName).ToList();

            return View(users);
        }
        #endregion

        #region 06，Identity Server 4 用户注册页面+IActionResult Register(string returnUrl = null)
        [HttpGet]
        [Route("Account/Register")]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }
        #endregion

        #region 07，Identity Server 4 用户注册操作+async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null, string roleName = "AdminTest")
        [HttpPost]
        [Route("Account/Register")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null, string roleName = "AdminTest")
        {
            ViewData["ReturnUrl"] = returnUrl;
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var userItem = _userManager.FindByNameAsync(model.LoginName).Result;

                if (userItem == null)
                {

                    var user = new ApplicationUser
                    {
                        Email = model.Email,
                        UserName = model.LoginName,
                        LoginName = model.RealName,
                        Sex = model.Sex,
                        Age = model.Birth.Year - DateTime.Now.Year,
                        Birthday = model.Birth,
                        Address = "",
                        IsDelete = false
                    };


                    result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        result = await _userManager.AddClaimsAsync(user, new Claim[]{
                            new Claim(JwtClaimTypes.Name, model.RealName),
                            new Claim(JwtClaimTypes.Email, model.Email),
                            new Claim(JwtClaimTypes.EmailVerified, "false", ClaimValueTypes.Boolean),
                            new Claim(JwtClaimTypes.Role, roleName)
                        });

                        if (result.Succeeded)
                        {
                            // 可以直接登录
                            //await _signInManager.SignInAsync(user, isPersistent: false);

                            if (Url.IsLocalUrl(returnUrl))
                            {
                                return Redirect(returnUrl);
                            }
                            else
                            {
                                return RedirectToAction(nameof(HomeController.Index), "Home");
                            }
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{userItem?.UserName} already exists");

                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }
        #endregion

        #region 08，Identity Server 4 edit user page+async Task<IActionResult> Edit(string id, string returnUrl = null)
        /// <summary>
        /// 编辑用户页面
        /// </summary>
        /// <param name="id">userId</param>
        /// <param name="returnUrl">return url address</param>
        /// <returns></returns>
        [HttpGet("{id}")]
        [Route("Account/EditUser/{id}")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> Edit(string id, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (id == null)
            {
                return NotFound();
            }

            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return View(new EditUserViewModel(user.Id.ToString(), user.LoginName, user.UserName, user.Email));
        }
        #endregion

        #region 09，Identity Server 4 edit user operation+async Task<IActionResult> Edit(EditUserViewModel model, string id, string returnUrl = null)
        /// <summary>
        /// edit user operation 
        /// </summary>
        /// <param name="model"></param>
        /// <param name="id"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("Account/Edit/{id}")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> Edit(EditUserViewModel model, string id, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var userItem = _userManager.FindByIdAsync(model.Id).Result;

                if (userItem != null)
                {
                    userItem.UserName = model.LoginName;
                    userItem.LoginName = model.UserName;
                    userItem.Email = model.Email;
                    userItem.RealName = model.UserName;


                    result = await _userManager.UpdateAsync(userItem);

                    if (result.Succeeded)
                    {
                        return RedirectToLocal(returnUrl);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{userItem?.UserName} no exist!");
                }

                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }
        #endregion

        /// <summary>
        /// 添加异常信息
        /// </summary>
        /// <param name="result"></param>
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        /// <summary>
        /// 跳转
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}
