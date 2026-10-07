import { getUserInfoForUid2 } from "../user";
import { doAddDataExportTask } from "../utils/common";
import Config from "../config";
import { failJson } from "../utils/fail";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { UserInfo } from "../d";

const s3Client = new S3Client({ region: Config.awsRegion });

function handle_GET_dataExport(
  req: { p: { uid?: number; zid: number; unixTimestamp: number; format: any } },
  res: { json: (arg0: {}) => void }
) {
  getUserInfoForUid2(req.p.uid)
    .then((user: UserInfo) => {
      return doAddDataExportTask(
        Config.mathEnv,
        user.email!,
        req.p.zid,
        req.p.unixTimestamp * 1000,
        req.p.format,
        Math.abs((Math.random() * 999999999999) >> 0)
      )
        .then(() => {
          res.json({});
        })
        .catch((err: any) => {
          failJson(res, 500, "polis_err_data_export123", err);
        });
    })
    .catch((err: any) => {
      failJson(res, 500, "polis_err_data_export123b", err);
    });
}

async function handle_GET_dataExport_results(
  req: { p: { filename: string } },
  res: { redirect: (arg0: string) => void }
) {
  try {
    const url = await getSignedUrl(
      s3Client,
      new GetObjectCommand({
        Bucket: "polis-datadump",
        Key: Config.mathEnv + "/" + req.p.filename,
      }),
      { expiresIn: 60 * 60 * 24 * 7 }
    );
    res.redirect(url);
  } catch (err) {
    failJson(res, 500, "polis_err_data_export_results", err);
  }
}

export { handle_GET_dataExport, handle_GET_dataExport_results };
