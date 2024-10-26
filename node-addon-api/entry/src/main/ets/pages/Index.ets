import { hilog } from '@kit.PerformanceAnalysisKit';
import testNapi from 'libentry.so';

@Entry
@Component
struct Index {
  @State message: string = 'Hello World';

  build() {
    Row() {
      Column() {
        Text(this.message)
          .fontSize(50)
          .fontWeight(FontWeight.Bold)
          .onClick(() => {
            const ret = testNapi.add(2, 3);
            hilog.info(0x0000, 'testTag', 'Test NAPI 2 + 3 = %{public}d', ret);
          })
      }
      .width('100%')
    }
    .height('100%')
  }
}
