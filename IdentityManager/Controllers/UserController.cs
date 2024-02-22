using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext context;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;

        public UserController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            this.context = context;
            this.userManager = userManager;
            this.roleManager = roleManager;
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

        public async Task<IActionResult> ManageRole(string userId)
        {
            ApplicationUser user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            List<string> existingUserRoles = await userManager.GetRolesAsync(user) as List<string>;
            var model = new RolesViewModel { User = user };

            foreach (var role in roleManager.Roles)
            {
                RoleSelection roleSelection = new RoleSelection { RoleName = role.Name };
                if (existingUserRoles.Any(r => r == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RolesList.Add(roleSelection);
            }
            return View(model);
        }
    }
}
