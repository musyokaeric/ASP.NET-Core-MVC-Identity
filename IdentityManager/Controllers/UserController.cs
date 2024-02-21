using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext context;
        private readonly UserManager<ApplicationUser> userManager;

        public UserController(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
        {
            this.context = context;
            this.userManager = userManager;
        }

        public IActionResult Index()
        {
            var users = context.ApplicationUser.ToList();
            var userRoles = context.UserRoles.ToList();
            var roles = context.Roles.ToList();

            foreach (var user in users)
            {
                var userRole = userRoles.FirstOrDefault(u => u.UserId == user.Id);
                if (userRole == null)
                {
                    user.Role = "none";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(r => r.Id == userRole.RoleId).Name;
                }
            }

            return View(users);
        }
    }
}
