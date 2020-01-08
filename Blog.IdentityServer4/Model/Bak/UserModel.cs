using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Blog.IdentityServer4.Model.Bak
{
    /// <summary>
    /// 用户信息表
    /// </summary>
    public class UserModel
    {
        public UserModel() { }

        public UserModel(string loginName, string loginPwd)
        {
            LoginName = loginName;
            LoginPwd = loginPwd;
            UserName = loginName;
            Status = 0;
            CreateTime = DateTime.Now;
            ModifyTime = DateTime.Now;
            LastErrTime = DateTime.Now;
            ErrorCount = 0;
            UserName = "";

        }
        /// <summary>
        /// 用户Id
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// 登录账号
        /// </summary>
        public string LoginName { get; set; }

        /// <summary>
        /// 登录密码
        /// </summary>
        public string LoginPwd { get; set; }

        /// <summary>
        /// 状态
        /// </summary>
        public int Status { get; set; }
        /// <summary>
        /// 备注
        /// </summary>
        public string Remark { get; set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTime CreateTime { get; set; } = DateTime.Now;

        /// <summary>
        /// 更新时间
        /// </summary>
        public DateTime ModifyTime { get; set; } = DateTime.Now;

        /// <summary>
        ///最后登录时间 
        /// </summary>
        public DateTime LastErrTime { get; set; } = DateTime.Now;

        /// <summary>
        ///错误次数 
        /// </summary>
        public int ErrorCount { get; set; }

        /// <summary>
        /// 登录账号
        /// </summary>
        public string UserName { get; set; }


        public string RoleName { get; set; }

        // 性别
        public int Sex { get; set; } = 0;
        // 年龄
        public int Age { get; set; }
        // 生日
        public DateTime Brithday { get; set; } = DateTime.Now;
        // 地址
        public string Address { get; set; }

        public bool IsDeleted { get; set; }
    }
}
