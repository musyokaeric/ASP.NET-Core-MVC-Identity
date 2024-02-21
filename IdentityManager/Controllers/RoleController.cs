using IdentityManager.Data;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext context;

        public RoleController(ApplicationDbContext context)
        {
            this.context = context;
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
    }
}
