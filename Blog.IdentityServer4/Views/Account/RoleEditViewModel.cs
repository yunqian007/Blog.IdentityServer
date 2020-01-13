using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Blog.IdentityServer4.Views.Account
{
    public class RoleEditViewModel
    {
        public RoleEditViewModel()
        {

        }
        public RoleEditViewModel(string Id, string Name)
        {
            this.Id = Id;
            this.RoleName = Name;
        }

        public string Id { get; set; }

        [Required]
        [Display(Name = "角色名")]
        public string RoleName { get; set; }


    }
}
