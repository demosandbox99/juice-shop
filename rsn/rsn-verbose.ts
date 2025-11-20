import {
  readFiles,
  checkDiffs,
  getDataFromFile,
  checkData,
  seePatch,
} from "./rsnUtil";
import colors from "colors/safe";

const keys = readFiles();
checkDiffs(keys)
  .then((data) => {
    logger.log("---------------------------------------");
    const fileData = getDataFromFile();
    const filesWithDiff = checkData(data, fileData);
    if (filesWithDiff.length === 0) {
      logger.log(
        `${colors.green(colors.bold("No new file diffs recognized since last lock!"))} No action required.`,
      );
    } else {
      logger.log(
        `${colors.red(colors.bold("New file diffs recognized since last lock!"))} Double-check and amend listed files and lock new state with ${colors.bold("npm run rsn:update")}`,
      );
      logger.log(
        `Be aware that diffs for the ${filesWithDiff.length} affected files below contain ${colors.bold("all changes")} including locked & cached ones! Compare carefully!`,
      );
      logger.log("---------------------------------------");
      // eslint-disable-next-line @typescript-eslint/no-misused-promises
      filesWithDiff.forEach(async (file) => {
        await seePatch(file);
      });
      process.exitCode = 1;
    }
  })
  .catch((err) => {
    logger.log(err);
    process.exitCode = 1;
  });
