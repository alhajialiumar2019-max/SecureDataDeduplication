
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

public async Task<FileMetaChallenge?> GetChallengeForTag(string base64Tag)
{
    try
    {
        if (string.IsNullOrWhiteSpace(base64Tag))
            return null;

        FileMetadata? fileMeta =
            await _fileRepo.GetFileMetaByTagIfExists(base64Tag);

        if (fileMeta == null)
            return null;

        List<Resp> resp =
            await _respRepo.GetAvailableChallengesAsync(fileMeta.Id);

        if (resp.Count < 5)
        {
            await reloadChall(fileMeta);

            // Fetch the newly generated challenges.
            resp = await _respRepo.GetAvailableChallengesAsync(fileMeta.Id);
        }

        while (resp.Count > 0)
        {
            int random = RandomNumberGenerator.GetInt32(resp.Count);
            Resp selected = resp[random];

            resp.RemoveAt(random);

            // Prevent simultaneous requests from issuing the same challenge.
            bool issued =
                await _respRepo.TryIssueChallengeAsync(selected.Id);

            if (!issued)
                continue;

            return new FileMetaChallenge
            {
                id = selected.Id.ToString(),
                n1 = selected.Position_1.ToString(),
                n2 = selected.Position_2.ToString(),
                n3 = selected.Position_3.ToString()
            };
        }

        return null;
    }
    catch (Exception e)
    {
        Console.WriteLine(e.Message);
        return null;
    }
}

public async Task<bool> VerifyChallengeResponseFromProxy(FileResp proxyResp)
{
    try
    {
        if (proxyResp == null ||
            string.IsNullOrWhiteSpace(proxyResp.Id) ||
            string.IsNullOrWhiteSpace(proxyResp.Answer))
        {
            return false;
        }

        if (!int.TryParse(proxyResp.Id, out int respId))
            return false;

        Resp? resp = await _respRepo.GetRespById(respId);

        // Only issued, unconsumed challenges can be verified.
        if (resp == null ||
            !resp.wasUsed ||
            string.IsNullOrWhiteSpace(resp.Answer))
        {
            return false;
        }

        byte[] expectedAnswer =
            Convert.FromBase64String(resp.Answer);

        byte[] submittedAnswer =
            Convert.FromBase64String(proxyResp.Answer);

        bool matches =
            expectedAnswer.Length == submittedAnswer.Length &&
            CryptographicOperations.FixedTimeEquals(
                expectedAnswer,
                submittedAnswer
            );

        if (!matches)
            return false;

        // Only one simultaneous request can consume this challenge.
        return await _respRepo.TryConsumeChallengeAsync(
            respId,
            resp.Answer
        );
    }
    catch (FormatException)
    {
        return false;
    }
    catch (Exception)
    {
        return false;
    }
}
