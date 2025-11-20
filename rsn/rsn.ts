import { readFiles, checkDiffs, getDataFromFile, checkData } from "./rsnUtil";
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
      logger.log("---------------------------------------");
      process.exitCode = 1;
    }
  })
  .catch((err) => {
    logger.log(err);
    process.exitCode = 1;
  });
