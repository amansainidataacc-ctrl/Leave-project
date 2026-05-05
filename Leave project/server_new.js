async function updateLeaveStatus(req, res, status) {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
            success: false,
            message: "Invalid leave request"
        });
    }

    try {
        const [rows] = await db.execute("SELECT * FROM leaves WHERE id=?", [id]);

        if (!rows.length) {
            return res.status(404).json({
                success: false,
                message: "Leave request not found"
            });
        }

        const leave = rows[0];
        await db.execute("UPDATE leaves SET status=? WHERE id=?", [status, id]);

        try {
            const emailResult = await sendStatusEmail(leave, status);
            const emailMessage = emailResult.sent ? "Email sent" : emailResult.reason;

            res.json({
                success: true,
                message: `${status}. ${emailMessage}.`
            });
        } catch (emailErr) {
            console.log(`${status} email error:`, emailErr.message);
            res.json({
                success: true,
                message: `${status}, but email failed.`
            });
        }
    } catch (err) {
        console.log(`${status} DB error:`, err.message);
        res.status(500).json({
            success: false,
            message: "Database error"
        });
    }
}

async function startServer() {
    // Start listening immediately so static files are served even if DB is connecting
    app.listen(PORT, HOST, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });

    try {
        await ensureDatabaseExists();
        db = createDatabasePool();
        await db.query("SELECT 1");
        console.log("MySQL Connected");
        await initializeDatabase();

        if (!process.env.TOKEN_SECRET) {
            console.log("TOKEN_SECRET is not set. Set it in Railway for stable secure admin sessions.");
        }

        const cleanupTimer = setInterval(() => {
            Promise.all([cleanupExpiredLeaves()]).catch((err) => {
                console.log("Leave cleanup error:", err.message);
            });
        }, LEAVE_CLEANUP_INTERVAL_MS);
        cleanupTimer.unref?.();
    } catch (err) {
        console.log("Startup Database Error:", err);
        console.log("Server is still running to serve static files, but database features will fail.");
    }
}

startServer();
