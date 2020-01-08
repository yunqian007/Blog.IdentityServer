using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Blog.IdentityServer4.Model.Bak
{
    public class UserRoleModel : RootEntity
    {
        public UserRoleModel() { }

        public UserRoleModel(int uId, int rId)
        {
            UserId = uId;
            RoleId = rId;
            CreateTime = DateTime.Now;
            IsDeleted = false;
            CreateId = uId;
            CreateTime = DateTime.Now;
        }

        /// <summary>
        ///获取或设置是否禁用，逻辑上的删除，非物理删除
        /// </summary>
        public bool IsDeleted { get; set; } = false;
        /// <summary>
        /// 用户ID
        /// </summary>
        public int UserId { get; set; }
        /// <summary>
        /// 角色ID
        /// </summary>
        public int RoleId { get; set; }
        /// <summary>
        /// 创建ID
        /// </summary>
        public int? CreateId { get; set; }
        /// <summary>
        /// 创建者
        /// </summary>
        public string CreateBy { get; set; }
        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTime? CreateTime { get; set; } = DateTime.Now;
        /// <summary>
        /// 修改ID
        /// </summary>
        public int? ModifyId { get; set; }
        /// <summary>
        /// 修改者
        /// </summary>
        public string ModifyBy { get; set; }
        /// <summary>
        /// 修改时间
        /// </summary>
        public DateTime? ModifyTime { get; set; } = DateTime.Now;

    }
}
