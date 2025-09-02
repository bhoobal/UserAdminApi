using Microsoft.AspNetCore.Mvc;
using Microsoft.FeatureManagement;
using Microsoft.OpenApi.Models;
using UserAdminApi.Models;
using UserAdminApi.Repositories;
using UserAdminApi.Services;

var builder = WebApplication.CreateBuilder(args);

// Feature flags
builder.Services.AddFeatureManagement(builder.Configuration.GetSection("FeatureManagement"));

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "User Management API",
        Version = "v1",
        Description = "Minimal API for user administration with optional encryption and pluggable storage (JSON or MongoDB)."
    });
});

// Config: choose storage by environment variable
// STORAGE_PROVIDER = "json" (default) or "mongodb"
var storageProvider = Environment.GetEnvironmentVariable("STORAGE_PROVIDER")?.ToLowerInvariant() ?? "json";

if (storageProvider == "mongodb")
{
    builder.Services.AddSingleton<IUserRepository>(sp =>
    {
        var cfg = sp.GetRequiredService<IConfiguration>();
        var conn = Environment.GetEnvironmentVariable("MONGODB_URI")
                  ?? cfg.GetConnectionString("Mongo") 
                  ?? "mongodb://localhost:27017";
        var db = Environment.GetEnvironmentVariable("MONGODB_DB") 
                  ?? cfg.GetValue<string>("Mongo:Database") 
                  ?? "UserAdminDb";
        var coll = Environment.GetEnvironmentVariable("MONGODB_COLLECTION") 
                  ?? cfg.GetValue<string>("Mongo:Collection") 
                  ?? "users";
        return new MongoUserRepository(conn, db, coll);
    });
}
else
{
    builder.Services.AddSingleton<IUserRepository>(sp =>
    {
        var cfg = sp.GetRequiredService<IConfiguration>();
        var path = Environment.GetEnvironmentVariable("USERS_JSON_PATH") 
                   ?? cfg.GetValue<string>("JsonStorage:Path") 
                   ?? Path.Combine(AppContext.BaseDirectory, "Data", "users.json");
        return new JsonUserRepository(path);
    });
}

// Encryption service chosen by feature flag "EncryptUserData"
builder.Services.AddSingleton<IEncryptionService>(sp =>
{
    var cfg = sp.GetRequiredService<IConfiguration>();
    var featureManager = sp.GetRequiredService<IFeatureManager>();
    var flagEnabled = cfg.GetValue<bool?>("FeatureManagement:EncryptUserData") ?? false;

    // Key & IV can come from env vars or config; generate defaults for dev
    var keyB64 = Environment.GetEnvironmentVariable("ENCRYPTION_KEY_BASE64") ?? cfg["Encryption:KeyBase64"];
    var ivB64 = Environment.GetEnvironmentVariable("ENCRYPTION_IV_BASE64") ?? cfg["Encryption:IVBase64"];

    if (!flagEnabled)
    {
        return new NoOpEncryptionService();
    }

    if (string.IsNullOrWhiteSpace(keyB64) || string.IsNullOrWhiteSpace(ivB64))
    {
        // Generate a random key/iv in dev scenarios; log a console warning
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("WARNING: Encryption feature is enabled but no key/iv provided via ENCRYPTION_KEY_BASE64 / ENCRYPTION_IV_BASE64. Generating a volatile key for this process.");
        Console.ResetColor();
        return AesEncryptionService.CreateWithRandomKey();
    }

    return new AesEncryptionService(Convert.FromBase64String(keyB64), Convert.FromBase64String(ivB64));
});

builder.Services.AddSingleton<PasswordHasher>();

var app = builder.Build();

// Swagger
if (app.Environment.IsDevelopment() || app.Configuration.GetValue<bool>("EnableSwagger"))
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Minimal API endpoints
app.MapGet("/", () => Results.Redirect("/swagger"));

// List users
app.MapGet("/api/users", async ([FromServices] IUserRepository repo, [FromServices] IEncryptionService enc) =>
{
    var users = await repo.GetAllAsync();
    return Results.Ok(users.Select(u => u.AsDto(enc)));
})
.WithName("GetUsers")
.WithTags("Users");

// Get single user
app.MapGet("/api/users/{id}", async ([FromRoute] string id, [FromServices] IUserRepository repo, [FromServices] IEncryptionService enc) =>
{
    var user = await repo.GetByIdAsync(id);
    return user is null ? Results.NotFound() : Results.Ok(user.AsDto(enc));
})
.WithName("GetUserById")
.WithTags("Users");

// Create user
app.MapPost("/api/users", async ([FromBody] CreateUserRequest req, [FromServices] IUserRepository repo, [FromServices] IEncryptionService enc, [FromServices] PasswordHasher hasher) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest("Username and password are required.");

    var existing = await repo.GetByUsernameAsync(req.Username);
    if (existing is not null) return Results.Conflict($"Username '{req.Username}' already exists.");

    var (hash, salt) = hasher.HashPassword(req.Password);

    var user = new User
    {
        Id = Guid.NewGuid().ToString("N"),
        Username = req.Username,
        EmailEncrypted = enc.Encrypt(req.Email ?? ""),
        FullNameEncrypted = enc.Encrypt(req.FullName ?? ""),
        PasswordHash = hash,
        PasswordSalt = salt,
        CreatedUtc = DateTimeOffset.UtcNow
    };

    await repo.CreateAsync(user);
    return Results.Created($"/api/users/{user.Id}", user.AsDto(enc));
})
.WithName("CreateUser")
.WithTags("Users");

// Update user
app.MapPut("/api/users/{id}", async ([FromRoute] string id, [FromBody] UpdateUserRequest req, [FromServices] IUserRepository repo, [FromServices] IEncryptionService enc, [FromServices] PasswordHasher hasher) =>
{
    var user = await repo.GetByIdAsync(id);
    if (user is null) return Results.NotFound();

    if (!string.IsNullOrWhiteSpace(req.Email)) user.EmailEncrypted = enc.Encrypt(req.Email);
    if (!string.IsNullOrWhiteSpace(req.FullName)) user.FullNameEncrypted = enc.Encrypt(req.FullName);
    if (!string.IsNullOrWhiteSpace(req.Password))
    {
        var (hash, salt) = hasher.HashPassword(req.Password);
        user.PasswordHash = hash;
        user.PasswordSalt = salt;
    }
    await repo.UpdateAsync(user);
    return Results.Ok(user.AsDto(enc));
})
.WithName("UpdateUser")
.WithTags("Users");

// Delete user
app.MapDelete("/api/users/{id}", async ([FromRoute] string id, [FromServices] IUserRepository repo) =>
{
    var ok = await repo.DeleteAsync(id);
    return ok ? Results.NoContent() : Results.NotFound();
})
.WithName("DeleteUser")
.WithTags("Users");

app.Run();

namespace UserAdminApi.Models
{
    public record CreateUserRequest(string Username, string? Email, string? FullName, string Password);
    public record UpdateUserRequest(string? Email, string? FullName, string? Password);

    public sealed class User
    {
        public string Id { get; set; } = default!;
        public string Username { get; set; } = default!;
        public string EmailEncrypted { get; set; } = default!;
        public string FullNameEncrypted { get; set; } = default!;
        public string PasswordHash { get; set; } = default!;
        public string PasswordSalt { get; set; } = default!;
        public DateTimeOffset CreatedUtc { get; set; }

        public UserDto AsDto(Services.IEncryptionService enc) => new UserDto
        {
            Id = Id,
            Username = Username,
            Email = enc.Decrypt(EmailEncrypted),
            FullName = enc.Decrypt(FullNameEncrypted),
            CreatedUtc = CreatedUtc
        };
    }

    public sealed class UserDto
    {
        public string Id { get; set; } = default!;
        public string Username { get; set; } = default!;
        public string Email { get; set; } = default!;
        public string FullName { get; set; } = default!;
        public DateTimeOffset CreatedUtc { get; set; }
    }
}

namespace UserAdminApi.Services
{
    public interface IEncryptionService
    {
        string Encrypt(string plaintext);
        string Decrypt(string ciphertext);
        bool IsEnabled { get; }
    }

    public sealed class NoOpEncryptionService : IEncryptionService
    {
        public bool IsEnabled => false;
        public string Encrypt(string plaintext) => plaintext;
        public string Decrypt(string ciphertext) => ciphertext;
    }

    public sealed class AesEncryptionService : IEncryptionService
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;
        public bool IsEnabled => true;

        public AesEncryptionService(byte[] key, byte[] iv)
        {
            if (key.Length != 32) throw new ArgumentException("Key must be 256-bit (32 bytes).");
            if (iv.Length != 16) throw new ArgumentException("IV must be 128-bit (16 bytes).");
            _key = key;
            _iv = iv;
        }

        public static AesEncryptionService CreateWithRandomKey()
        {
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            aes.GenerateIV();
            return new AesEncryptionService(aes.Key, aes.IV);
        }

        public string Encrypt(string plaintext)
        {
            if (string.IsNullOrEmpty(plaintext)) return plaintext;
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            using var encryptor = aes.CreateEncryptor();
            var plainBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            return Convert.ToBase64String(cipherBytes);
        }

        public string Decrypt(string ciphertext)
        {
            if (string.IsNullOrEmpty(ciphertext)) return ciphertext;
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            using var decryptor = aes.CreateDecryptor();
            var cipherBytes = Convert.FromBase64String(ciphertext);
            var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
            return System.Text.Encoding.UTF8.GetString(plainBytes);
        }
    }

    public sealed class PasswordHasher
    {
        public (string hash, string salt) HashPassword(string password)
        {
            var saltBytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
            var saltB64 = Convert.ToBase64String(saltBytes);
            using var derive = new System.Security.Cryptography.Rfc2898DeriveBytes(password, saltBytes, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256);
            var hash = Convert.ToBase64String(derive.GetBytes(32));
            return (hash, saltB64);
        }
    }
}

namespace UserAdminApi.Repositories
{
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using UserAdminApi.Models;
    using MongoDB.Driver;

    public interface IUserRepository
    {
        Task<List<User>> GetAllAsync();
        Task<User?> GetByIdAsync(string id);
        Task<User?> GetByUsernameAsync(string username);
        Task CreateAsync(User user);
        Task UpdateAsync(User user);
        Task<bool> DeleteAsync(string id);
    }

    public sealed class JsonUserRepository : IUserRepository
    {
        private readonly string _path;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private List<User> _cache = new();

        public JsonUserRepository(string path)
        {
            _path = path;
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            if (File.Exists(_path))
            {
                var json = File.ReadAllText(_path);
                _cache = JsonSerializer.Deserialize<List<User>>(json, SerializerOptions()) ?? new List<User>();
            }
            else
            {
                PersistAsync().GetAwaiter().GetResult();
            }
        }

        public async Task<List<User>> GetAllAsync()
        {
            await _gate.WaitAsync();
            try { return _cache.Select(u => Clone(u)).ToList(); }
            finally { _gate.Release(); }
        }

        public async Task<User?> GetByIdAsync(string id)
        {
            await _gate.WaitAsync();
            try { return _cache.FirstOrDefault(u => u.Id == id) is { } u ? Clone(u) : null; }
            finally { _gate.Release(); }
        }

        public async Task<User?> GetByUsernameAsync(string username)
        {
            await _gate.WaitAsync();
            try { return _cache.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase)) is { } u ? Clone(u) : null; }
            finally { _gate.Release(); }
        }

        public async Task CreateAsync(User user)
        {
            await _gate.WaitAsync();
            try
            {
                _cache.Add(Clone(user));
                await PersistAsync();
            }
            finally { _gate.Release(); }
        }

        public async Task UpdateAsync(User user)
        {
            await _gate.WaitAsync();
            try
            {
                var idx = _cache.FindIndex(u => u.Id == user.Id);
                if (idx >= 0) _cache[idx] = Clone(user);
                await PersistAsync();
            }
            finally { _gate.Release(); }
        }

        public async Task<bool> DeleteAsync(string id)
        {
            await _gate.WaitAsync();
            try
            {
                var removed = _cache.RemoveAll(u => u.Id == id) > 0;
                if (removed) await PersistAsync();
                return removed;
            }
            finally { _gate.Release(); }
        }

        private async Task PersistAsync()
        {
            var json = JsonSerializer.Serialize(_cache, SerializerOptions());
            await File.WriteAllTextAsync(_path, json);
        }

        private static JsonSerializerOptions SerializerOptions() => new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private static User Clone(User u) => new()
        {
            Id = u.Id,
            Username = u.Username,
            EmailEncrypted = u.EmailEncrypted,
            FullNameEncrypted = u.FullNameEncrypted,
            PasswordHash = u.PasswordHash,
            PasswordSalt = u.PasswordSalt,
            CreatedUtc = u.CreatedUtc
        };
    }

    public sealed class MongoUserRepository : IUserRepository
    {
        private readonly IMongoCollection<User> _collection;
        public MongoUserRepository(string connectionString, string databaseName, string collectionName)
        {
            var client = new MongoClient(connectionString);
            var db = client.GetDatabase(databaseName);
            _collection = db.GetCollection<User>(collectionName);
        }

        public async Task<List<User>> GetAllAsync() =>
            await _collection.Find(_ => true).ToListAsync();

        public async Task<User?> GetByIdAsync(string id) =>
            await _collection.Find(u => u.Id == id).FirstOrDefaultAsync();

        public async Task<User?> GetByUsernameAsync(string username) =>
            await _collection.Find(u => u.Username == username).FirstOrDefaultAsync();

        public async Task CreateAsync(User user) =>
            await _collection.InsertOneAsync(user);

        public async Task UpdateAsync(User user) =>
            await _collection.ReplaceOneAsync(u => u.Id == user.Id, user);

        public async Task<bool> DeleteAsync(string id)
        {
            var res = await _collection.DeleteOneAsync(u => u.Id == id);
            return res.DeletedCount > 0;
        }
    }
}
