
import { sm2Decrypt, sm2Encrypt, sm3Encrypt, sm4Decrypt, sm4Encrypt} from 'libentry.so';

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
            const ret = sm2Encrypt("hello");

            const origin = sm2Decrypt(ret);

            const hash = sm3Encrypt("hello");

            const sm4Ret = sm4Encrypt("hello");
            const originSm4 = sm4Decrypt(sm4Ret);
            console.log(`${originSm4} ${origin} ${hash}`);
          })
      }
      .width('100%')
    }
    .height('100%')
  }
}
