import { afterEach, describe, expect, jest, test } from "@jest/globals";

import { getRegionFromIP } from "../../src/utils/moderation";

describe("native moderation region lookup", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test("returns the same ordered location fields from a successful lookup", async () => {
    const fetchMock = jest
      .spyOn(global, "fetch")
      .mockResolvedValue(
        new Response(
          JSON.stringify({
            status: "success",
            city: "Gunnedah",
            regionName: "New South Wales",
            country: "Australia",
          }),
          { status: 200 }
        )
      );

    await expect(getRegionFromIP("2001:db8::1")).resolves.toBe(
      "Gunnedah, New South Wales, Australia"
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://ip-api.com/json/2001%3Adb8%3A%3A1",
      expect.objectContaining({
        redirect: "follow",
        signal: expect.any(AbortSignal),
      })
    );
  });

  test("retains the fail-soft fallback for empty or unsuccessful data", async () => {
    const fetchMock = jest
      .spyOn(global, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ status: "fail" }), {
          status: 200,
        })
      );

    await expect(getRegionFromIP("")).resolves.toBe("US or Europe (EU)");
    expect(fetchMock).not.toHaveBeenCalled();
    await expect(getRegionFromIP("198.51.100.5")).resolves.toBe(
      "US or Europe (EU)"
    );
  });
});
