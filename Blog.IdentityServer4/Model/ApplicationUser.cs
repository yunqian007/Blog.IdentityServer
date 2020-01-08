using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Blog.IdentityServer4.Model
{
    public class ApplicationUser : IdentityUser<int>
    {

        public string LoginName { get; set; }

        public string RealName { get; set; }

        public int Sex { get; set; } = 0;

        public int Age { get; set; }

        public DateTime Birthday { get; set; } = DateTime.Now;

        public string Address { get; set; }

        public bool IsDelete { get; set; }

        public ICollection<ApplicationUserRole> UserRoles { get; set; }
    }
}
