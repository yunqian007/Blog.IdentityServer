using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Blog.IdentityServer4.Quickstart.Account
{
    public class RoleRegisterViewModel
    {

        [Required]
        [Display(Name = "角色名")]
        public string RoleName { get; set; }


    }
}
