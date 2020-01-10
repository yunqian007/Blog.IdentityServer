using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Blog.IdentityServer4.Quickstart.Account
{
    public class EditUserViewModel
    {
        public EditUserViewModel()
        {

        }
        public EditUserViewModel(string Id, string Name, string LoginName, string Email)
        {
            this.Id = Id;
            this.LoginName = LoginName;
            this.Email = Email;
            this.UserName = Name;
        }

        public string Id { get; set; }

        [Required]
        [Display(Name = "昵称")]
        public string UserName { get; set; }

        [Required]
        [Display(Name = "登录名")]
        public string LoginName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "邮箱")]
        public string Email { get; set; }


        [Display(Name = "性别")]
        public int Sex { get; set; } = 0;

        [Display(Name = "生日")]
        public DateTime Birthday { get; set; } = DateTime.Now;
    }
}
