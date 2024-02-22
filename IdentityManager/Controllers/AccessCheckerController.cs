using Microsoft.AspNetCore.Authorization;
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
        public IActionResult Admin_CreateEditDelete_Access()
        {
            return View();
        }

        // Only Eric can access this endpoint
        public IActionResult OnlyEric_Access()
        {
            return View();
        }
    }
}
