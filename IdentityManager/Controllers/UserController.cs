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

        public async Task<IActionResult> Index()
        {
            var users = context.ApplicationUser.ToList();

            foreach (var user in users)
            {
                var userRoles = await userManager.GetRolesAsync(user) as List<string>;
                user.Role = string.Join(", ", userRoles);
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
        {
            ApplicationUser user = await userManager.FindByIdAsync(rolesViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }

            var oldUserRoles = await userManager.GetRolesAsync(user);
            var result = await userManager.RemoveFromRolesAsync(user, oldUserRoles);
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while removing roles";
                return View(rolesViewModel);
            }

            var stringRoles = rolesViewModel.RolesList.Where(r => r.IsSelected).Select(r => r.RoleName);

            result = await userManager.AddToRolesAsync(user, rolesViewModel.RolesList.Where(r => r.IsSelected).Select(r => r.RoleName));
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while adding roles";
                return View(rolesViewModel);
            }

            TempData[SD.Success] = "Roles added successfully";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> ManageUserClaim(string userId)
        {
            ApplicationUser user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var existingUserClaims = await userManager.GetClaimsAsync(user);
            var model = new ClaimsViewModel { User = user };

            foreach (var claim in ClaimStore.claimsList)
            {
                ClaimSelection claimSelection = new ClaimSelection { ClaimType = claim.Type };
                if (existingUserClaims.Any(c => c.Type == claim.Type))
                {
                    claimSelection.IsSelected = true;
                }
                model.ClaimList.Add(claimSelection);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaim(ClaimsViewModel claimsViewModel)
        {
            ApplicationUser user = await userManager.FindByIdAsync(claimsViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }

            var oldUserClaims = await userManager.GetClaimsAsync(user);
            var result = await userManager.RemoveClaimsAsync(user, oldUserClaims);
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while removing claims";
                return View(claimsViewModel);
            }

            result = await userManager.AddClaimsAsync(user, claimsViewModel.ClaimList
                .Where(c => c.IsSelected)
                .Select(c => new System.Security.Claims.Claim(c.ClaimType, c.IsSelected.ToString())));
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while adding claims";
                return View(claimsViewModel);
            }

            TempData[SD.Success] = "Claims added successfully";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
            ApplicationUser user = context.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }
            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                // User is locked and will remain locked until lockout end time
                // Clicking this action will unlock the user
                user.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked successfully";
            }
            else
            {
                // User is not locked, clicking this action will lock the user
                user.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User locked successfully";
            }
            
            await context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            var user = context.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }
            context.ApplicationUser.Remove(user);
            await context.SaveChangesAsync();
            TempData[SD.Success] = "User deleted successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}
