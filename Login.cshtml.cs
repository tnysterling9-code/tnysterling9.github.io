using System.Security.Claims;
using CleaningCompanyWeb.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MySqlConnector;

namespace CleaningCompanyWeb.Pages;

public class LoginModel : PageModel
{
    private readonly DatabaseConnection _db;
    private readonly IConfiguration _config;

    public LoginModel(DatabaseConnection db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    [BindProperty]
    public string Username { get; set; } = string.Empty;

    [BindProperty]
    public string Password { get; set; } = string.Empty;

    public string ErrorMessage { get; set; } = string.Empty;

    public void OnGet()
    {
        // Nothing to do - just render the form.
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password))
        {
            ErrorMessage = "Please enter both username and password.";
            return Page();
        }

        int maxFailedAttempts = _config.GetValue<int?>("AppSettings:MaxFailedLoginAttempts") ?? 5;

        try
        {
            await using MySqlConnection conn = _db.GetConnection();
            await conn.OpenAsync();

            const string sql =
                "SELECT ua.user_id, ua.password_hash, ua.is_active, ua.failed_login_attempts, ua.must_reset_password, " +
                "       e.employee_id, e.first_name, e.last_name, e.status AS employee_status, " +
                "       r.role_name, r.permission_level " +
                "FROM user_account ua " +
                "JOIN employee e ON e.employee_id = ua.employee_id " +
                "JOIN role r ON r.role_id = e.role_id " +
                "WHERE ua.username = @username " +
                "LIMIT 1;";

            await using var cmd = new MySqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@username", Username.Trim());

            await using var reader = await cmd.ExecuteReaderAsync();

            if (!await reader.ReadAsync())
            {
                ErrorMessage = "Invalid username or password.";
                return Page();
            }

            int userId = reader.GetInt32("user_id");
            string storedHash = reader.GetString("password_hash");
            bool isActive = reader.GetBoolean("is_active");
            int failedAttempts = reader.GetInt32("failed_login_attempts");
            bool mustResetPassword = reader.GetBoolean("must_reset_password");
            int employeeId = reader.GetInt32("employee_id");
            string firstName = reader.GetString("first_name");
            string lastName = reader.GetString("last_name");
            string employeeStatus = reader.GetString("employee_status");
            string roleName = reader.GetString("role_name");
            int permissionLevel = reader.GetInt32("permission_level");

            await reader.CloseAsync();

            if (!isActive)
            {
                ErrorMessage = "This account has been disabled. Contact your manager.";
                return Page();
            }

            if (!string.Equals(employeeStatus, "Active", StringComparison.OrdinalIgnoreCase))
            {
                ErrorMessage = "This employee record is not active.";
                return Page();
            }

            if (failedAttempts >= maxFailedAttempts)
            {
                ErrorMessage = "Account locked after too many failed attempts. Contact the CEO or your manager.";
                return Page();
            }

            if (!Security.VerifyPassword(Password, storedHash))
            {
                await RecordFailedAttemptAsync(conn, userId, failedAttempts + 1);
                int remaining = maxFailedAttempts - (failedAttempts + 1);
                ErrorMessage = remaining > 0
                    ? $"Invalid username or password. {remaining} attempt(s) remaining."
                    : "Invalid username or password. Account is now locked.";
                return Page();
            }

            // Success: reset failed attempts, stamp last_login.
            await ResetFailedAttemptsAndStampLoginAsync(conn, userId);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim("EmployeeId", employeeId.ToString()),
                new Claim(ClaimTypes.Name, $"{firstName} {lastName}"),
                new Claim(ClaimTypes.Role, roleName),
                new Claim("PermissionLevel", permissionLevel.ToString()),
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            // A temporary password (set when the CEO creates a new employee) must be
            // changed before the person can use anything else - sign-in already
            // happened above, so this redirect just routes them to the one page
            // they're allowed to act on first.
            if (mustResetPassword)
            {
                return RedirectToPage("/ChangePassword", new { forced = true });
            }

            return RedirectToPage("/Dashboard");
        }
        catch (MySqlException)
        {
            ErrorMessage = "Could not reach the database. Please check your connection settings.";
            return Page();
        }
        catch (Exception ex)
        {
            ErrorMessage = "An unexpected error occurred: " + ex.Message;
            return Page();
        }
    }

    private static async Task RecordFailedAttemptAsync(MySqlConnection conn, int userId, int newCount)
    {
        const string sql = "UPDATE user_account SET failed_login_attempts = @count WHERE user_id = @id;";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@count", newCount);
        cmd.Parameters.AddWithValue("@id", userId);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task ResetFailedAttemptsAndStampLoginAsync(MySqlConnection conn, int userId)
    {
        const string sql =
            "UPDATE user_account SET failed_login_attempts = 0, last_login = NOW() WHERE user_id = @id;";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@id", userId);
        await cmd.ExecuteNonQueryAsync();
    }
}
