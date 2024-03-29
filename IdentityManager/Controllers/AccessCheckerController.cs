﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        // Anyone can access this endpoint
        [AllowAnonymous]
        public IActionResult All_Access()
        {
            return View();
        }

        // As long as they are logged in, they can access this endpoint.
        public IActionResult Authorized_Access()
        {
            return View();
        }

        // If an account has "user" or "admin" role, they can access this endpoint
        [Authorize(Roles = $"{SD.Admin},{SD.User}")]
        public IActionResult UserOrAdminRole_Access()
        {
            return View();
        }

        // If an account has "user" AND "admin" role, they can access this endpoint
        [Authorize(Policy = "AdminANDUser")]
        public IActionResult UserANDAdminRole_Access()
        {
            return View();
        }

        // If an account has "admin" role, they can access this endpoint
        [Authorize(Roles = SD.Admin)]
        public IActionResult AdminRole_Access()
        {
            return View();
        }

        // If an account has "admin" role and "create" claim, they can access this endpoint
        [Authorize(Policy = "AdminRole_CreateClaim")]
        public IActionResult Admin_Create_Access()
        {
            return View();
        }

        // If an account has "admin" role, and ("create" & "edit" & "delete") claims, they can access this endpoint
        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim")]
        public IActionResult Admin_CreateEditDelete_Access()
        {
            return View();
        }

        // If an account has "admin" role, and ("create" & "edit" & "delete") claims OR has "superadmin" role, they can access this endpoint
        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole")]
        public IActionResult Admin_CreateEditDelete_Or_SuperAdminRole_Access()
        {
            return View();
        }

        // Only Eric (Admin Role, and user is more than 1000 days old) can access this endpoint
        [Authorize(Policy = "AdminWithMoreThan1000Days")]
        public IActionResult OnlyEric_Access()
        {
            return View();
        }

        // Custom policy handler with claims
        [Authorize(Policy = "FirstNameAuthorization")]
        public IActionResult FirstNameAuthorization_Access()
        {
            return View();
        }
    }
}
