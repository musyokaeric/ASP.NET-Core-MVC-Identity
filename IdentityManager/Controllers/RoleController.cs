﻿using IdentityManager.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace IdentityManager.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext context;
        private readonly RoleManager<IdentityRole> roleManager;

        public RoleController(ApplicationDbContext context, RoleManager<IdentityRole> roleManager)
        {
            this.context = context;
            this.roleManager = roleManager;
        }

        public IActionResult Index()
        {
            var roles = context.Roles.ToList();

            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string roleId)
        {
            if (string.IsNullOrEmpty(roleId))
            {
                // Create
                return View();
            }
            else
            {
                // Update
                var role = context.Roles.FirstOrDefault(x => x.Id == roleId);
                return View(role);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole role)
        {
            if (await roleManager.RoleExistsAsync(role.Name))
            {
                // Error
            }
            if (string.IsNullOrEmpty(role.NormalizedName))
            {
                // Create
                await roleManager.CreateAsync(new IdentityRole { Name = role.Name });
                TempData[SD.Success] = "Role created successfully";
            }
            else
            {
                // Update
                var roleFromDb = context.Roles.FirstOrDefault(x => x.Id == role.Id);
                roleFromDb.Name = role.Name;
                roleFromDb.NormalizedName = role.Name.ToUpper();
                var result = await roleManager.UpdateAsync(roleFromDb);
                TempData[SD.Success] = "Role updated successfully";
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        // [Authorize(Roles = SD.SuperAdmin)] // Simple handler: Only a super admin can delete a role
        [Authorize(Policy = "OnlySuperAdminRoleChecker")]
        public async Task<IActionResult> Delete(string roleId)
        {
            var role = context.Roles.FirstOrDefault(x => x.Id == roleId);
            if (role != null)
            {
                var userRoles = context.UserRoles.Where(u => u.RoleId == roleId).Count();
                if (userRoles > 0)
                {
                    TempData[SD.Error] = "Cannot delete this role, since there are users assigned to this role.";
                    return RedirectToAction(nameof(Index));
                }

                await roleManager.DeleteAsync(role);
                TempData[SD.Success] = "Role deleted successfully";
            }
            else
            {
                TempData[SD.Error] = "Role not found";
            }
            return RedirectToAction(nameof(Index));
        }
    }
}
