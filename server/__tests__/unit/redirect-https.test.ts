jest.mock("../../src/db/pg-query", () => ({
  __esModule: true,
  default: {},
}));

jest.mock("../../src/config", () => ({
  __esModule: true,
  default: {
    domainOverride: undefined,
    getServerHostname: () => "api.example.test",
    isDevMode: false,
    isTesting: false,
    nodeEnv: "production",
    staticFilesHost: "static.example.test",
    staticFilesParticipationPort: 443,
    useNetworkHost: false,
    whitelistItems: [],
  },
}));

import { redirectIfNotHttps } from "../../src/utils/domain";

describe("redirectIfNotHttps", () => {
  test("ends a rejected non-HTTPS write without continuing middleware", () => {
    const next = jest.fn();
    const send = jest.fn().mockReturnValue("sent");
    const status = jest.fn().mockReturnValue({ send });

    const result = redirectIfNotHttps(
      {
        headers: { host: "api.example.test" },
        method: "POST",
        path: "/api/v3/conversations",
        url: "/api/v3/conversations",
      },
      {
        end: jest.fn(),
        status,
        writeHead: jest.fn(),
      },
      next
    );

    expect(status).toHaveBeenCalledWith(400);
    expect(send).toHaveBeenCalledWith("Please use HTTPS when submitting data.");
    expect(next).not.toHaveBeenCalled();
    expect(result).toBe("sent");
  });

  test("continues an HTTPS request exactly once", () => {
    const next = jest.fn().mockReturnValue("continued");

    const result = redirectIfNotHttps(
      {
        headers: {
          host: "api.example.test",
          "x-forwarded-proto": "https",
        },
        method: "POST",
        path: "/api/v3/conversations",
        url: "/api/v3/conversations",
      },
      {
        end: jest.fn(),
        status: jest.fn(),
        writeHead: jest.fn(),
      },
      next
    );

    expect(next).toHaveBeenCalledTimes(1);
    expect(result).toBe("continued");
  });
});
