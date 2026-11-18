
using FileStorageApp.Server.Database;
using FileStorageApp.Server.Entity;
using Microsoft.EntityFrameworkCore;

namespace FileStorageApp.Server.Repositories
{
    public class RespRepository
    {
        private readonly DataContext _context;

        public RespRepository(DataContext context)
        {
            _context = context;
        }

        public async Task SaveResp(Resp resp)
        {
            _context.Resps.Add(resp);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateResp(Resp resp)
        {
            _context.Resps.Update(resp);
            await _context.SaveChangesAsync();
        }

        public async Task SaveMultipleResps(List<Resp> respList)
        {
            await _context.AddRangeAsync(respList);
            await _context.SaveChangesAsync();
        }

        public async Task<Resp?> GetRespById(int id)
        {
            return await _context.Resps
                .AsNoTracking()
                .FirstOrDefaultAsync(r => r.Id == id);
        }

        public async Task<List<Resp>> GetAvailableChallengesAsync(
            int fileMetadataId)
        {
            return await _context.Resps
                .AsNoTracking()
                .Where(r =>
                    r.FileMetadataId == fileMetadataId &&
                    !r.wasUsed)
                .ToListAsync();
        }

        // Atomically issue a challenge only once.
        public async Task<bool> TryIssueChallengeAsync(int id)
        {
            int affectedRows =
                await _context.Database.ExecuteSqlInterpolatedAsync(
                    $"UPDATE Resps SET wasUsed = 1 WHERE Id = {id} AND wasUsed = 0");

            return affectedRows == 1;
        }

        // Atomically consume a successfully verified challenge.
        public async Task<bool> TryConsumeChallengeAsync(
            int id, string expectedAnswer)
        {
            int affectedRows =
                await _context.Database.ExecuteSqlInterpolatedAsync(
                    $"UPDATE Resps SET Answer = '' WHERE Id = {id} AND wasUsed = 1 AND Answer = {expectedAnswer}");

            return affectedRows == 1;
        }
    }
}
