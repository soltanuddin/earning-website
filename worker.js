export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Test D1 connection
    if (url.pathname === "/api/test-db") {
      try {
        const result = await env.DB
          .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
          .all();

        return Response.json({
          success: true,
          tables: result.results
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }

    // Serve the website
    return env.ASSETS.fetch(request);
  }
};